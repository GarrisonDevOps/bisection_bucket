# frozen_string_literal: true

module WorkItems
  class StatusChangedEvent < BaseEvent
    event_type :status_changed

    class << self
      def build(work_item:, current_user:, status:)
        return if current_user.nil?
        return if status.nil?

        build_for_work_item(
          work_item: work_item,
          current_user: current_user,
          extra_event_data: {
            status: {
              name: status.name.to_s,
              category: status.category.to_s
            }
          }
        )
      end
    end

    private

    def additional_properties
      {
        'status' => {
          'type' => 'object',
          'properties' => {
            'name' => { 'type' => 'string' },
            'category' => { 'type' => 'string' }
          },
          'required' => %w[name category]
        }
      }
    end

    def additional_required
      %w[status]
    end
  end
end
