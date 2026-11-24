# frozen_string_literal: true

# NOTE: This is a convenience route helper method used in Rails view helpers to generate a path to pass
#       to the frontend workspaces Vue router logic with `new` as the `vueroute`. It is defined as a direct route
#       instead of a `new` route on the main `workspaces` resource route, because there's no actual routable
#       `#new` action on the workspaces controller, only `#index`.
direct :new_remote_development_workspace do
  "/-/remote_development/workspaces/new"
end
