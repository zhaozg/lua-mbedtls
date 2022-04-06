lua << EOF
  --lsp
  local setting = require'neospace.lsp'.setting
  local runtime_path = vim.split(package.path, ';')
  table.insert(runtime_path, "lua/?.lua")
  table.insert(runtime_path, "lua/?/init.lua")

  setting('sumneko_lua', { settings = {
    Lua = {
      runtime = {
        -- Tell the language server which version of Lua you're using (most likely LuaJIT in the case of Neovim)
        version = 'LuaJIT',
        -- Setup your lua path
        path = runtime_path,
      }
    }
  }})

  vim.api.nvim_create_autocmd("VimEnter", {
    callback = function()
      local git = require "nvim-tree.git"
      local project_root = git.get_project_root('.')
      --code format
      local fmt = require'neospace.fmt'
      fmt.c = {
        exe = "uncrustify",
        args = {"-q", "-l C", "-c", project_root..'/.uncrustify.conf'},
        stdin = true
      }
    end
  })

EOF
