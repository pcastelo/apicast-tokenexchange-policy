local policy = require('apicast.policy')
local _M = policy.new('Token Exchange Policy')
local http_ng = require('resty.http_ng')
local user_agent = require('apicast.user_agent')
local resty_url = require('resty.url')
local new = _M.new
local cjson = require('cjson.safe')
local user_agent = require 'apicast.user_agent'
local resty_env = require('resty.env')
local ipairs = ipairs
local http_proxy = require('resty.http.proxy')
local http_ng_ngx = require('resty.http_ng.backend.ngx')
local http_ng_resty = require('resty.http_ng.backend.resty')
local http_authorization = require('resty.http_authorization')
local errors = require('apicast.errors')
local setmetatable = setmetatable
local tostring = tostring
local JWT = require 'resty.jwt'
local jwt_validators = require 'resty.jwt-validators'
local assert = assert
local type = type


local http_ng_backend_phase = {
  access = http_ng_ngx,
  rewrite = http_ng_ngx,
  content = http_ng_ngx,
}


local function recover_referer(context)
    local referrer = ngx.var.http_referer
    if referrer then
        return referrer
    end
end

local jwt_mt = {
  __tostring = function(jwt)
    return jwt.token
  end
}


local function load_jwt(token)
  local jwt = JWT:load_jwt(tostring(token))

  jwt.token = token

  return setmetatable(jwt, jwt_mt)
end

function _M:parse(jwt, cache_key)
  local cached = cache_key and self.cache:get(cache_key)

  if cached then
    ngx.log(ngx.DEBUG, 'found JWT in cache for ', cache_key)
    return cached
  end

  return load_jwt(jwt)
end

-- Parses the token - in this case we assume it's a JWT token
-- Here we can extract authenticated user's claims or other information returned in the access_token
-- or id_token by RH SSO
local function parse_and_verify_token(self, namespace, jwt_token)
  local cache = self.cache

  if not cache then
    return nil, 'not initialized'
  end
  local cache_key = format('%s:%s', namespace or '<empty>', jwt_token)

  local jwt = self:parse(jwt_token, cache_key)

  if jwt.verified then
    return jwt
  end

  local _, err = self:verify(jwt, cache_key)

  return jwt, err
end

function _M:parse_and_verify(access_token, cache_key)
  local jwt_obj, err = parse_and_verify_token(self, assert(cache_key, 'missing cache key'), access_token)

  if err then
    if ngx.config.debug then
      ngx.log(ngx.DEBUG, 'JWT object: ', require('inspect')(jwt_obj), ' err: ', err, ' reason: ', jwt_obj.reason)
    end
    return nil, jwt_obj and jwt_obj.reason or err
  end

  return jwt_obj
end

local function detect_http_client(endpoint)
  local uri = resty_url.parse(endpoint)
  local proxy = http_proxy.find(uri)

  if proxy then -- use default client
    return
  else
    return http_ng_backend_phase[ngx.get_phase()]
  end
end

local function obtain_account(endpoint, access_token, userName, context)

  local url = endpoint .. "/admin/api/accounts/find.json?access_token=".. access_token .. "&username=" .. userName
    
  local http_client = detect_http_client(endpoint)
  
  local res, err http_client.get { url }
  
  if res.status == 200 then
   
     local account, decode_err = cjson.decode(res.body)
   
     if  not account then
          ngx.log(ngx.ERR, 'Account Id:', account.id)
          return account.id
     else
         ngx.log(ngx.ERR, 'failed to parse account response:', decode_err)
     end
     
   else 
         ngx.log(ngx.ERR, 'failed to retrieve account response:', res.status)  
   end
    
   return nil
end

local function obtain_application(endpoint, access_token, account_id, service_id, context)

  local http_client = detect_http_client(endpoint)
  
  local url = endpoint .. "/" .. "admin/api/accounts/" .. account_id .. "/applications.json?access_token=" .. access_token 
  
  local res, err = http_client.get { url }
  
  if res.status == 200 then
   
     local applications, decode_err = cjson.decode(res.body)
   
     if type(applications) == 'table' then
        ngx.log(ngx.ERR, 'Applications found:', #applications)
          for i=1,#applications do
              local application = applications[i]
              if not application then
                return errors.no_credentials(service)
              else 
                if application.user_service_id == service_id then
                   return application.application_id
                end
              end
          end
        ngx.log(ngx.ERR, 'No application found for service id:', service_id)
        return nil
     else
         ngx.log(ngx.ERR, 'failed to parse applications response:', decode_err)
     end
     
   else 
         ngx.log(ngx.ERR, 'failed to retrieve account response:', res.status)  
   end
    
   return nil
end

function _M.new(config, context)

    local self = new(config)
    self.endpoint = resty_env.value("BACKEND_ENDPOINT_OVERRIDE")
    
    self.config = config or {}
    self.exchange_url = config.exchange_url
    self.referer = recover_referer(context)
    self.secret_token = resty_env.enabled('SECRET_ACCESS_TOKEN')

    self.http_client = http_ng.new {
        backend = config.client,
        options = {
            headers = {
                ['User-Agent'] = user_agent()
            },
            ssl = { verify = resty_env.enabled('OPENSSL_VERIFY') }
        }
    }
    return self
end




local function exchange_token(self, token, application_id)
    ngx.log(ngx.INFO, 'REFERERR:', self.referer)
    local body = {}
    --ngx.req.read_body() or

    body["referer"]= self.referer
    body["audience"] = application_id
    body["subject_token"] = token

    local res, err = self.http_client.post {
        self.exchange_url, body,
        headers = { ['Authorization'] = self.credential }
    }
    
    if res.status == 200 then
        local access_token, decode_err = cjson.decode(res.body)
        if type(access_token) == 'table' then
            self.new_authorization = access_token
            return self
        else
            ngx.log(ngx.ERR, 'failed to parse access_token response:', decode_err)
            return { active = false }
        end
    else
        ngx.log(ngx.WARN, 'failed to execute access_token status: ', res.status)
        return { active = false }
    end
end

function _M:access(context)

    local account_id =  nil
    local service_id = nil
    local application_id = nil
    
    local service = context.service    
    
    local jwt_obj, err = self:parse_and_verify(self.access_token, self.cache_key or '<shared>')
    
    local token_payload = jwt_obj.payload;
    
    local endpoint = self.endpoint or (service and service.backend and service.backend.endpoint) or error('missing endpoint')
    
    if not service then
      ngx.log(ngx.ERROR, 'no service id in context: ', service)
      return errors.service_not_found(ngx.var.host)
    else
      service_id = service.id
      account_id = obtain_account(endpoint, self.access_token, token_payload.preferred_username, context)
      if not account_id then
        ngx.log(ngx.ERROR, 'no account_id in context: ', account_id)
        ngx.status = context.service.auth_failed_status
        ngx.say(context.service.error_auth_failed)
        return ngx.exit(ngx.status)
      end
      application_id =  obtain_application(endpoint, self.access_token, account_id, service_id, context)
      if not application_id  then 
      
        ngx.log(ngx.ERROR, 'no application_id found for context: ', application_id)
        ngx.status = context.service.auth_failed_status
        ngx.say(context.service.error_auth_failed)
        return ngx.exit(ngx.status)
      end      
    end
    
    for k,v in ipairs(context) do
        ngx.log(ngx.INFO, 'CONTEXT:', k,v)
    end

    ngx.log(ngx.INFO, 'REFERERR:', self.referer)
    
    local authorization = http_authorization.new(ngx.var.http_authorization)

    exchange_token(self, authorization.token, application_id)
end


local function new_header_value(current_value, value_to_add)
    if not value_to_add then return current_value end

    local new_value = current_value or {}

    if type(new_value) == 'string' then
        new_value = { new_value }
    end

    insert(new_value, value_to_add)
    return new_value
end

function _M:header_filter(context)
    local new_value = new_header_value(ngx.header['Authorization'], context.new_authorization)
    ngx.header['Authorization'] = new_value
end




return _M
