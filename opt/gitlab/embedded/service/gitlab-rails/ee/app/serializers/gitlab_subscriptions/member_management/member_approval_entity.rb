# frozen_string_literal: true

module GitlabSubscriptions
  module MemberManagement
    class MemberApprovalEntity < Grape::Entity
      include RequestAwareEntity

      expose :id
      expose :created_at
      expose :updated_at

      expose :requested_by, if: ->(member_approval) { member_approval.requested_by.present? } do |member_approval|
        UserEntity.represent(member_approval.requested_by, only: [:name, :web_url])
      end

      expose :reviewed_by, if: ->(member_approval) { member_approval.reviewed_by.present? } do |member_approval|
        UserEntity.represent(member_approval.reviewed_by, only: [:name, :web_url])
      end

      expose :new_access_level do
        expose :human_new_access_level, as: :string_value
        expose :new_access_level, as: :integer_value
        expose :member_role_id
      end

      expose :old_access_level, if: ->(member_approval) { member_approval.old_access_level.present? } do
        expose :human_old_access_level, as: :string_value
        expose :old_access_level, as: :integer_value
      end

      expose :source do
        expose :source_id, as: :id
        expose :source_name, as: :full_name
        expose :source_web_url, as: :web_url
      end

      expose :user do |member_approval|
        MemberUserEntity.represent(member_approval.user, options)
      end

      private

      alias_method :member_approval, :object

      def presenter
        @member_presenter ||= member_approval.present
      end

      def human_new_access_level
        presenter.human_new_access_level
      end

      def human_old_access_level
        presenter.human_old_access_level
      end

      def source_id
        presenter.source_id
      end

      def source_name
        presenter.source_name
      end

      def source_web_url
        presenter.source_web_url
      end
    end
  end
end
