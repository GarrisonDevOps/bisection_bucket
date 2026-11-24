# frozen_string_literal: true

module Tasks
  module Gitlab
    module Nav
      class DumpStructure
        attr_accessor :context_defaults, :user

        def initialize(user:)
          @user = user
          @context_defaults = {
            current_user: @user,
            is_super_sidebar: true,

            # Turn features on that impact the list of items rendered
            can_view_pipeline_editor: true,
            show_discover_group_security: true,
            show_discover_project_security: true,
            show_security_dashboard: true,

            # Turn features off that do not add/remove items
            show_cluster_hint: false,
            show_promotions: false,

            current_ref: 'master'
          }
        end

        def panels
          panels = []
          panels << Sidebars::UserProfile::Panel.new(Sidebars::Context.new(
            container: @user,
            **@context_defaults
          ))
          panels << Sidebars::UserSettings::Panel.new(Sidebars::Context.new(
            container: @user,
            **@context_defaults
          ))
          panels << Sidebars::YourWork::Panel.new(Sidebars::Context.new(
            container: @user,
            **@context_defaults
          ))
          panels << Sidebars::Projects::SuperSidebarPanel.new(Sidebars::Projects::Context.new(
            container: Project.first,
            **@context_defaults
          ))
          panels << Sidebars::Groups::SuperSidebarPanel.new(Sidebars::Groups::Context.new(
            container: Group.first,
            **@context_defaults
          ))
          panels << Sidebars::Organizations::Panel.new(Sidebars::Context.new(
            container: @user.organization,
            **@context_defaults
          ))
          panels << Sidebars::Admin::Panel.new(Sidebars::Context.new(
            container: nil,
            current_organization: @user.organization,
            **@context_defaults
          ))
          panels << Sidebars::Explore::Panel.new(Sidebars::Context.new(
            container: nil,
            current_organization: @user.organization,
            **@context_defaults
          ))

          panels
        end

        def current_time
          Time.now.utc.iso8601
        end

        def current_sha
          `git rev-parse --short HEAD`.strip
        end

        def dump(tags: nil)
          contexts = panels.map do |panel|
            {
              title: panel.aria_label,
              items: panel.super_sidebar_menu_items
            }
          end

          # Recurse through structure to drop info we don't need
          clean_keys!(contexts)
          tag_keys!(contexts, tags) if tags

          contexts
        end

        private

        def clean_keys!(entries)
          entries.each do |entry|
            clean_keys!(entry[:items]) if entry[:items]

            entry[:id] = entry[:id].to_s if entry[:id]
            entry.slice!(:id, :title, :icon, :link, :items)
          end
        end

        def tag_keys!(entries, tags)
          entries.each do |entry|
            tag_keys!(entry[:items], tags) if entry[:items]

            entry[:tags] = tags
          end
        end
      end
    end
  end
end
