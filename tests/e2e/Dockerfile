# Playwright test runner
# Uses the official Microsoft image which bundles Chromium, Firefox, WebKit
# and all OS-level dependencies needed to run them headlessly.
FROM mcr.microsoft.com/playwright:v1.61.1-noble@sha256:5b8f294aff9041b7191c34a4bab3ac270157a28774d4b0660e9743297b697e48

WORKDIR /tests

# Install Node deps first (cached layer)
COPY package*.json ./
RUN npm ci

# Copy test source
COPY . .

# Results volume — mounted by docker-compose so reports survive container exit
VOLUME ["/test-results"]

# Default: run the full suite; override CMD to run a subset
CMD ["npx", "playwright", "test", "--reporter=list"]
