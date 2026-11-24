# Labkit RSpec Support

This module provides RSpec matchers for testing Labkit functionality in your Rails applications.

## Setup

You must explicitly require the RSpec matchers in your test files:

```ruby
# In your spec_helper.rb or rails_helper.rb
require 'labkit/rspec/matchers'
```

This approach ensures that:
- Test dependencies are not loaded in production environments
- You have explicit control over which matchers are available
- The gem remains lightweight for non-testing use cases


## Available Matchers

### User Experience Matchers

These matchers help you test that your code properly instruments user experience SLIs with the expected metrics.

#### `start_user_experience`

Tests that a user experience is started (checkpoint=start metric is incremented).

```ruby
expect { subject }.to start_user_experience('rails_request')

# Test that it does NOT start
expect { subject }.not_to start_user_experience('rails_request')
```

#### `checkpoint_user_experience`

Tests that a user experience checkpoint is recorded (checkpoint=intermediate metric is incremented).

```ruby
expect { subject }.to checkpoint_user_experience('rails_request')

# Test that it does NOT checkpoint
expect { subject }.not_to checkpoint_user_experience('rails_request')
```

#### `resume_user_experience`

Tests that a user experience is resumed (checkpoint=intermediate metric is incremented). This is an alias for `checkpoint_user_experience` that provides more semantic meaning when testing code that resumes a user experience previously started.

```ruby
expect { subject }.to resume_user_experience('rails_request')

# Test that it does NOT resume
expect { subject }.not_to resume_user_experience('rails_request')
```

#### `complete_user_experience`

Tests that a user experience is completed with the expected metrics:
- `gitlab_user_experience_checkpoint_total` (with checkpoint=end)
- `gitlab_user_experience_total` (with error flag)
- `gitlab_user_experience_apdex_total` (with success flag)

```ruby
# Test successful completion
expect { subject }.to complete_user_experience('rails_request')

# Test completion with error
expect { subject }.to complete_user_experience('rails_request', error: true, success: false)

# Test that it does NOT complete
expect { subject }.not_to complete_user_experience('rails_request')
```

## Example Usage

### In your spec_helper.rb or rails_helper.rb:

```ruby
# spec/spec_helper.rb or spec/rails_helper.rb
require 'gitlab-labkit'

# Explicitly require the RSpec matchers
require 'labkit/rspec/matchers'

RSpec.configure do |config|
  # Your other RSpec configuration...
end
```

### In your test files:

```ruby
RSpec.describe MyController, type: :controller do
  describe '#index' do
    it 'instruments the request properly' do
      expect { get :index }.to start_user_experience('rails_request')
        .and complete_user_experience('rails_request')
    end

    context 'when an error occurs' do
      before do
        allow(MyService).to receive(:call).and_raise(StandardError)
      end

      it 'records the error in metrics' do
        expect { get :index }.to complete_user_experience('rails_request', error: true, success: false)
      end
    end
  end
end
```

### For individual spec files (alternative approach):

```ruby
# spec/controllers/my_controller_spec.rb
require 'spec_helper'
require 'labkit/rspec/matchers' # Can also be required per-file if needed

RSpec.describe MyController do
  # Your tests using the matchers...
end
```

## Requirements

- The user experience SLI must be registered in `Labkit::UserExperienceSli::Registry`
- Metrics must be properly configured in your test environment
- The code under test must use Labkit's user experience SLI instrumentation
