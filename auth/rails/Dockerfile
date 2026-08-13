FROM ruby:4.0-slim
WORKDIR /app
COPY Gemfile Gemfile.lock ./
RUN bundle config set without test && bundle install
COPY . .
CMD ["bundle", "exec", "rails", "server", "-b", "0.0.0.0", "-p", "8080"]
