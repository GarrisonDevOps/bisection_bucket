# frozen_string_literal: true

module DeclarativePolicy
  module PreferredScope
    PREFERRED_SCOPE_KEY = :'DeclarativePolicy.preferred_scope'

    # Scores depend on the preferred scope (see ManifestCondition#score), so
    # changing it advances the score epoch. The scope is per fiber but the
    # epoch is not, so fibers sharing a cache with different scopes may see
    # each other's scores. That can only change the order of checks.
    def with_preferred_scope(scope)
      old_scope = Thread.current[PREFERRED_SCOPE_KEY]
      self.preferred_scope = scope
      yield
    ensure
      self.preferred_scope = old_scope
    end

    def preferred_scope
      Thread.current[PREFERRED_SCOPE_KEY]
    end

    def user_scope(&block)
      with_preferred_scope(:user, &block)
    end

    def subject_scope(&block)
      with_preferred_scope(:subject, &block)
    end

    def preferred_scope=(scope)
      return if Thread.current[PREFERRED_SCOPE_KEY] == scope

      Thread.current[PREFERRED_SCOPE_KEY] = scope
      DeclarativePolicy.advance_score_epoch!
    end
  end
end
