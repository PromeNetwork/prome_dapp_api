FROM node:20-alpine 
WORKDIR /app

COPY package*.json ./
RUN yarn install --non-interactive --frozen-lockfile
COPY . .
RUN yarn  build

CMD [ "node", "dist/main.js" ]