local policy = require('apicast.policy')
local _M = policy.new('Token Exchange Policy')
local http_ng = require 'resty.http_ng'
local new = _M.new
local cjson = require('cjson.safe')
local user_agent = require 'apicast.user_agent'
local resty_env = require('resty.env')

local function recover_referer(context)
    local referrer = ngx.var.http_referer
    if referrer then
        return referrer
    end
end

function _M.new(config, context)
    local self = new(config)
    ngx.log(ngx.INFO, 'context:', context)
    self.config = config or {}
    self.exchange_url = config.exchange_url
    self.referer = recover_referer(context)

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

local function exchange_token(self)
    ngx.log(ngx.INFO, 'REFERERR:', self.referer)
    local body = ngx.req.read_body()
    body.insert("referer", self.referer)
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
    ngx.log(ngx.INFO, 'CONTEXT:', context)
    ngx.log(ngx.INFO, 'SELF:', self)
    ngx.log(ngx.INFO, 'REFERERR:', self.referer)
    exchange_token(self)
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
