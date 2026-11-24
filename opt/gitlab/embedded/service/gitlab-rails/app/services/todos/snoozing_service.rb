# frozen_string_literal: true

# SnoozingService class
#
# Used for snoozing/un-snoozing todos
#
# Ex.
#   Todos::SnoozingService.new.snooze_todo(todo, 1.day.from_now)
#
# A snoozed todo leaves the pending count (the pending scope is
# `not_snoozed`) and an un-snoozed one re-enters it, so every change here
# schedules the mobile app badge re-send (TodoService#enqueue_badge_sync).
module Todos
  class SnoozingService
    def snooze_todo(todo, snooze_until)
      if todo.update(snoozed_until: snooze_until)
        enqueue_badge_sync(todo.user_id)
        ServiceResponse.success(payload: { todo: todo })
      else
        ServiceResponse.error(message: todo.errors.full_messages)
      end
    end

    def un_snooze_todo(todo)
      if todo.snoozed_until.nil?
        ServiceResponse.success(payload: { todo: todo })
      elsif todo.update(snoozed_until: nil)
        enqueue_badge_sync(todo.user_id)
        ServiceResponse.success(payload: { todo: todo })
      else
        ServiceResponse.error(message: todo.errors.full_messages)
      end
    end

    def snooze_todos(todos, snooze_until)
      todos.batch_update(snoozed_until: snooze_until).tap { |ids| enqueue_badge_sync_for(ids) }
    end

    def unsnooze_todos(todos)
      todos.batch_update(snoozed_until: nil).tap { |ids| enqueue_badge_sync_for(ids) }
    end

    private

    def enqueue_badge_sync(user_ids)
      ::TodoService.new.enqueue_badge_sync(user_ids)
    end

    # The bulk paths get ids back, not users, so the user ids are a query:
    # run only once the feature's flags pass (a dark feature costs nothing)
    # and after the update, which is safe because snoozing never changes a
    # todo's user. The mutations behind these paths scope the todos to the
    # current user, so the query yields that one id.
    def enqueue_badge_sync_for(todo_ids)
      return if todo_ids.empty? || !::TodoService.badge_sync_enabled?

      enqueue_badge_sync(Todo.id_in(todo_ids).distinct_user_ids)
    end
  end
end
