# frozen_string_literal: true

module EE
  module ProtectedRef
    def protected_ref_access_levels(*types)
      super

      types.each do |type|
        # Returns access levels that grant the specified access type to the given user / group.
        access_level_class = const_get("#{type}_access_level".classify, false)
        protected_type = model_name.singular
        scope :"#{type}_access_by_user", ->(user) do
          access_level_class.joins(protected_type.to_sym)
            .where("#{protected_type}_id" => ids)
            .merge(access_level_class.by_user(user))
        end
        scope :"#{type}_access_by_group", ->(group) do
          access_level_class.joins(protected_type.to_sym)
            .where("#{protected_type}_id" => ids)
            .merge(access_level_class.by_group(group))
        end
      end
    end
  end
end
