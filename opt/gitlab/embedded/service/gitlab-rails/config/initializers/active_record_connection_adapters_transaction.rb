# frozen_string_literal: true

if Rails.gem_version >= Gem::Version.new('8.2')
  raise 'Given that we are relying on a few Rails internal in ' \
    '`app/models/cells/transaction_record.rb`, we should verify if ' \
    'the contract still holds. If it does, please bump the version here.'
  # Review it with a local Rails git diff like this:
  # git diff v8.1.0..v8.2.0 --color-words -- activerecord/lib/active_record/connection_adapters/abstract/transaction.rb
  # The upstream file as of Rails 8.1 is at:
  # https://github.com/rails/rails/blob/v8.1.3.1/activerecord/lib/active_record/connection_adapters/abstract/transaction.rb
  # Other files might have impact but this is the most important one to review
end

ActiveRecord::ConnectionAdapters::Transaction.prepend(Cells::TransactionRecord::TransactionExtension)
