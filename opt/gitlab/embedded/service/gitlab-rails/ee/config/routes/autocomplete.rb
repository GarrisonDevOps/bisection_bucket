# frozen_string_literal: true

scope '/autocomplete', controller: :autocomplete, as: :autocomplete do
  get '/project_groups' => :project_groups
  get '/project_routes' => :project_routes
  get '/namespace_routes' => :namespace_routes
  get '/group_subgroups' => :group_subgroups
end
