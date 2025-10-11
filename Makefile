.PHONY: setup test type-check lint format format-check clean server test-integration build

setup:
	npm install

test:
	npm test

type-check:
	npm run type-check

lint:
	npm run lint

format:
	npm run format

format-check:
	npm run format:check

server:
	npm run server

test-integration:
	npm run test:integration

build:
	npm run build

clean:
	rm -rf node_modules dist
