# frozen_string_literal: true

module API
  module Entities
    class SSHKey < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 1, desc: 'ID of the key.' }
      expose :title, documentation: { type: 'String', example: 'Sample key 25', desc: 'Title of the key.' }
      expose :created_at, documentation: { type: 'DateTime', example: '2015-09-03T07:24:44.627Z',
                                           desc: 'Creation date and time of the key in ISO 8601 format.' }
      expose :expires_at, documentation: { type: 'DateTime', example: '2020-09-03T07:24:44.627Z',
                                           desc: 'Expiration date and time of the key in ISO 8601 format.' }
      expose :last_used_at, documentation: { type: 'DateTime', example: '2020-09-03T07:24:44.627Z',
                                             desc: 'Last usage date and time of the key in ISO 8601 format.' }
      expose :publishable_key, as: :key, documentation:
        { type: 'String',
          desc: 'Content of the key.',
          example: 'ssh-rsa AAAAB3NzaC1yc2EAAAABJQAAAIEAiPWx6WM4lhHNedGfBpPJNPpZ7yKu+dnn1SJejgt1256k6Yjz\
      GGphH2TUxwKzxcKDKKezwkpfnxPkSMkuEspGRt/aZZ9wa++Oi7Qkr8prgHc4soW6NUlfDzpvZK2H5E7eQaSeP3SAwGmQKUFHCdd\
      NaP0L+hM7zhFNzjFvpaMgJw0=' }
      expose :usage_type, documentation: {
        type: 'String', example: 'auth',
        desc: 'Usage type of the key: `auth`, `signing`, or `auth_and_signing`. ' \
          'Deploy keys always use `auth_and_signing`.'
      }
    end
  end
end
