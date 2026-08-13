FROM ruby:4.0-slim
RUN apt-get update && apt-get install -y --no-install-recommends build-essential libsqlite3-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Gemfile Gemfile.lock ./
RUN bundle config set without test && bundle install
COPY . .
CMD ["bundle", "exec", "rails", "server", "-b", "0.0.0.0", "-p", "8080"]
