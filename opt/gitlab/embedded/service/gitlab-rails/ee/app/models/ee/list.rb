# frozen_string_literal: true

module EE
  module List
    extend ::Gitlab::Utils::Override

    include ::Gitlab::Utils::StrongMemoize

    LIMIT_METRIC_TYPES = %w[all_metrics issue_count issue_weights].freeze

    # When adding a new licensed type, make sure to also add
    # it on license.rb with the pattern "board_<list_type>_lists"
    LICENSED_LIST_TYPES = %i[assignee milestone iteration status].freeze

    # ActiveSupport::Concern does not prepend the ClassMethods,
    # so we cannot call `super` if we use it.
    def self.prepended(base)
      base.include(UsageStatistics)
      base.include(::Boards::Lists::HasStatus)
      base.include(ActiveRecord::FixedItemsModel::HasOne)

      class << base
        prepend ClassMethods
      end

      base.belongs_to :user
      base.belongs_to :milestone
      base.belongs_to :iteration
      base.belongs_to_fixed_items :system_defined_status, fixed_items_class: ::WorkItems::Statuses::SystemDefined::Status, foreign_key: 'system_defined_status_identifier'
      base.belongs_to :custom_status, class_name: '::WorkItems::Statuses::Custom::Status', optional: true

      base.validates :user, presence: true, if: :assignee?
      base.validates :milestone, presence: true, if: :milestone?
      base.validates :iteration, presence: true, if: :iteration?
      base.validates :user_id, uniqueness: { scope: :board_id }, if: :assignee?
      base.validates :milestone_id, uniqueness: { scope: :board_id }, if: :milestone?
      base.validates :iteration_id, uniqueness: { scope: :board_id }, if: :iteration?
      base.validates :max_issue_count, numericality: { only_integer: true, greater_than_or_equal_to: 0 }
      base.validates :max_issue_weight, numericality: { only_integer: true, greater_than_or_equal_to: 0 }
      base.validates :limit_metric, inclusion: {
        in: LIMIT_METRIC_TYPES,
        allow_blank: true,
        allow_nil: true
      }
      base.validates :list_type,
        exclusion: { in: %w[assignee], message: ->(_object, _data) { _('Assignee lists not available with your current license') } },
        unless: -> { board&.resource_parent&.feature_available?(:board_assignee_lists) }
      base.validates :list_type,
        exclusion: { in: %w[milestone], message: ->(_object, _data) { _('Milestone lists not available with your current license') } },
        unless: -> { board&.resource_parent&.feature_available?(:board_milestone_lists) }
      base.validates :list_type,
        exclusion: { in: %w[iteration], message: ->(_object, _data) { _('Iteration lists not available with your current license') } },
        unless: -> { board&.resource_parent&.feature_available?(:board_iteration_lists) }
      base.validates :list_type,
        exclusion: { in: %w[status], message: ->(_object, _data) { _('Status lists not available with your current license') } },
        unless: -> { board&.resource_parent&.feature_available?(:board_status_lists) }

      base.validates_with ExactlyOnePresentValidator, fields: [:system_defined_status, :custom_status], if: :status?
      base.validate :validate_status_uniqueness, if: :status?
    end

    def assignee=(user)
      self.user = user
    end

    def validate_status_uniqueness
      return unless board

      status_id = system_defined_status_identifier || custom_status_id
      status_column = system_defined_status.present? ? :system_defined_status_identifier : :custom_status_id

      existing_list = board.lists.status
                           .where(status_column => status_id)
                           .where.not(id: id)
                           .exists?

      errors.add(:base, _('A list for this status already exists on the board')) if existing_list
    end

    def wip_limits_available?
      strong_memoize(:wip_limits_available) do
        board.resource_parent.feature_available?(:wip_limits)
      end
    end

    override :title
    def title
      case list_type
      when 'assignee'
        user.to_reference
      when 'milestone'
        milestone.title
      when 'iteration'
        iteration.display_text
      when 'status'
        status.name
      else
        super
      end
    end

    def status
      # Board lists don't use status mappings since they lack work item type and
      # timestamp context required for mapping resolution.
      return custom_status if custom_status.present?

      system_defined_status&.converted_status_in_namespace(
        board.resource_parent.root_ancestor
      )
    end

    def status=(new_status)
      return unless status?

      case new_status
      when ::WorkItems::Statuses::SystemDefined::Status
        self.system_defined_status = new_status
        self.custom_status = nil
      when ::WorkItems::Statuses::Custom::Status
        self.custom_status = new_status
        self.system_defined_status = nil
      end
    end

    override :as_json
    def as_json(options = {})
      super.tap do |json|
        if options.key?(:user)
          json[:user] = ::UserSerializer.new.represent(user).as_json
        end

        if options.key?(:milestone)
          json[:milestone] = MilestoneSerializer.new.represent(milestone).as_json
        end

        if options.key?(:iteration)
          json[:iteration] = IterationSerializer.new.represent(iteration).as_json
        end
      end
    end

    module ClassMethods
      def destroyable_types
        super + [:assignee, :milestone, :iteration, :status]
      end

      def movable_types
        super + [:assignee, :milestone, :iteration, :status]
      end
    end
  end
end
