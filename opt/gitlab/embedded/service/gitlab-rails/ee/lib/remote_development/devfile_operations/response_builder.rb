# frozen_string_literal: true

module RemoteDevelopment
  module DevfileOperations
    class ResponseBuilder
      include Messages

      # @param [Object] _context
      # @return [Gitlab::Fp::Result]
      def self.build(_context)
        Gitlab::Fp::Result.ok(DevfileValidateSuccessful.new({}))
      end
    end
  end
end
