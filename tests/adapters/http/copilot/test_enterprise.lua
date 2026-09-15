local new_set = MiniTest.new_set
local T = new_set()

T["enterprise authentication"] = new_set()

T["enterprise authentication"]["reads the Copilot CLI config and exchanges its token"] = function()
  local config_path = vim.fn.tempname() .. ".json"
  vim.fn.writefile({
    vim.json.encode({ oauth_token = "enterprise-oauth-token" }),
  }, config_path)

  local requests = {}
  local curl = require("plenary.curl")
  local original_get = curl.get
  curl.get = function(url)
    table.insert(requests, url)
    return {
      status = 200,
      body = vim.json.encode({
        token = "enterprise-copilot-token",
        expires_at = os.time() + 3600,
        endpoints = { api = "https://api.enterprise.example" },
      }),
    }
  end

  local token = require("codecompanion.adapters.http.copilot.token")
  token._oauth_token = nil
  token._copilot_token = nil
  local initialized = token.init({
    opts = {
      copilot_config_path = config_path,
      enterprise_uri = "https://github.enterprise.example",
      token_url = "https://auth.enterprise.example/copilot/token",
    },
  })
  curl.get = original_get

  MiniTest.expect.equality({
    initialized = initialized,
    oauth_token = token.fetch().oauth_token,
    copilot_token = token.fetch().copilot_token,
    request_url = requests[1],
  }, {
    initialized = true,
    oauth_token = "enterprise-oauth-token",
    copilot_token = "enterprise-copilot-token",
    request_url = "https://auth.enterprise.example/copilot/token",
  })
end

return T
