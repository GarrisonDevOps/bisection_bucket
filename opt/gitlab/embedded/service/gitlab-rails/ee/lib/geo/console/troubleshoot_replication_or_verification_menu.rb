# frozen_string_literal: true

module Geo
  module Console
    class TroubleshootReplicationOrVerificationMenu < MultipleChoiceMenu
      def name
        "Troubleshoot replication or verification"
      end

      def choices
        Gitlab::Geo.replication_enabled_replicator_classes.map do |replicator_class|
          TroubleshootReplicationOrVerificationForReplicatorClassMenu.new(
            **next_choice_args.merge(replicator_class: replicator_class))
        end + [

          *(if Gitlab::Geo.secondary_or_org_migration_target?
              [
                ShowCachedSecondarySiteStatusAction.new(**next_choice_args),
                ShowUncachedSecondarySiteStatusAction.new(**next_choice_args)
              ]
            end),

          ShowAllSiteStatusDataAction.new(**next_choice_args)
        ]
      end
    end
  end
end
