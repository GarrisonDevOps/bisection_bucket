# frozen_string_literal: true

module EE
  module SortingTitlesValuesHelper
    def sort_title_start_date
      s_('SortOptions|Start date')
    end

    def sort_title_end_date
      s_('SortOptions|Due date')
    end

    def sort_title_less_weight
      s_('SortOptions|Less weight')
    end

    def sort_title_more_weight
      s_('SortOptions|More weight')
    end

    def sort_title_weight
      s_('SortOptions|Weight')
    end

    def sort_title_blocking
      s_('SortOptions|Blocking')
    end

    def sort_value_start_date
      'start_date_asc'
    end

    def sort_value_end_date
      'end_date_asc'
    end

    def sort_value_less_weight
      'weight_asc'
    end

    def sort_value_more_weight
      'weight_desc'
    end

    def sort_value_weight
      'weight'
    end

    def sort_value_blocking_desc
      'blocking_issues_desc'
    end
  end
end
