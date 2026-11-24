# frozen_string_literal: true

module Gitlab
  module Analytics
    module CycleAnalytics
      extend Gitlab::Allowable

      class << self
        def licensed?(subject)
          case subject
          when Namespaces::ProjectNamespace
            project = subject.project
            project.licensed_feature_available?(:cycle_analytics_for_projects)
          when Group
            subject.licensed_feature_available?(:cycle_analytics_for_groups)
          when Namespaces::UserNamespace
            # Under a personal namespace, you can only create projects so it would be the project-level version of VSA
            subject.licensed_feature_available?(:cycle_analytics_for_projects)
          else
            false
          end
        end

        def allowed?(user, subject)
          ability_allowed?(:read_cycle_analytics, user, subject)
        end

        def allowed_to_edit?(user, subject)
          ability_allowed?(:create_value_stream, user, subject) ||
            ability_allowed?(:update_value_stream, user, subject) ||
            ability_allowed?(:delete_value_stream, user, subject)
        end

        def subject_for_access_check(subject)
          case subject
          when Namespaces::ProjectNamespace, Group
            subject.owner_entity
          else
            raise ArgumentError, "Unsupported subject given"
          end
        end

        def ability_allowed?(ability, user, subject)
          case subject
          when Namespaces::ProjectNamespace, Group
            can?(user, ability, subject_for_access_check(subject))
          else
            false
          end
        end
      end
    end
  end
end
