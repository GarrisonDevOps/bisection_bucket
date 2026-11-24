# frozen_string_literal: true

module GitlabSubscriptions
  module UserAddOnAssignments
    class BaseCreateService < ::BaseService
      include Gitlab::Utils::StrongMemoize

      ERROR_NO_SEATS_AVAILABLE = 'NO_SEATS_AVAILABLE'
      ERROR_INVALID_USER_MEMBERSHIP = 'INVALID_USER_MEMBERSHIP'
      ERROR_SEAT_ASSIGNMENT_NOT_SUPPORTED = 'SEAT_ASSIGNMENT_NOT_SUPPORTED'
      VALIDATION_ERROR_CODE = 422

      NoSeatsAvailableError = Class.new(StandardError) do
        def initialize(message = ERROR_NO_SEATS_AVAILABLE)
          super(message)
        end
      end

      def initialize(add_on_purchase:, user:)
        @add_on_purchase = add_on_purchase
        @user = user
      end

      def execute
        return ServiceResponse.success if user_already_assigned?

        error = validate

        if error.present?
          log_event('User AddOn assignment creation failed', error: error, error_code: VALIDATION_ERROR_CODE)
          return ServiceResponse.error(message: error)
        end

        add_on_purchase.with_lock do
          raise NoSeatsAvailableError unless seats_available?

          add_on_purchase.assigned_users.create!(user: user)

          Rails.cache.delete(::Ai::UserAuthorizer.duo_pro_cache_key_formatted(user.id))

          log_event('User AddOn assignment created')
        end

        after_success_hook

        ServiceResponse.success
      rescue NoSeatsAvailableError => error
        Gitlab::ErrorTracking.log_exception(
          error, base_log_params.merge({ message: 'User AddOn assignment creation failed' })
        )

        ServiceResponse.error(message: error.message)
      end

      private

      attr_reader :add_on_purchase, :user

      def after_success_hook
        todo_service.duo_pro_access_granted(user) if duo_pro?
        todo_service.duo_enterprise_access_granted(user) if duo_enterprise?
      end

      def duo_pro?
        add_on_purchase.add_on.code_suggestions?
      end

      def duo_enterprise?
        add_on_purchase.add_on.duo_enterprise?
      end

      def todo_service
        TodoService.new
      end
      strong_memoize_attr :todo_service

      def validate
        return ERROR_NO_SEATS_AVAILABLE unless seats_available?
        return ERROR_SEAT_ASSIGNMENT_NOT_SUPPORTED unless add_on_purchase.add_on_seat_assignable?

        ERROR_INVALID_USER_MEMBERSHIP unless eligible_for_gitlab_duo_pro_seat?
      end

      def seats_available?
        add_on_purchase.quantity > assigned_seats
      end

      def assigned_seats
        add_on_purchase.assigned_users.count
      end

      def user_already_assigned?
        add_on_purchase.already_assigned?(user)
      end
      strong_memoize_attr :user_already_assigned?

      def eligible_for_gitlab_duo_pro_seat?
        raise NotImplementedError, 'Subclasses must implement the eligible_for_gitlab_duo_pro_seat? method'
      end

      def log_event(message, error: nil, error_code: nil)
        log_params = base_log_params.tap do |result|
          result[:message] = message
          result[:error] = error if error
          result[:error_code] = error_code if error_code
        end

        Gitlab::AppLogger.info(log_params)
      end

      def base_log_params
        {
          username: user.username.to_s,
          add_on: add_on_purchase.add_on.name
        }
      end
    end
  end
end
