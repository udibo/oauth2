/**
 * The server entry React Router builds into `build/server/index.js`: one Hono
 * app that runs the auth layer and hands every other request to React Router.
 * Requests are logged with their query values redacted, so reset, verification
 * and callback credentials stay out of the server output.
 *
 * @module
 */

import { createHonoServer } from "react-router-hono-server/node";

import { requestLogger } from "@udibo/oauth2/hono/log";

import auth from "./auth.ts";
import { config } from "./config.ts";
import { createLoadContext } from "./load-context.ts";

export default await createHonoServer({
  port: config.port,
  defaultLogger: false,
  configure(app) {
    app.use(requestLogger());
    app.route("/", auth);
  },
  getLoadContext: createLoadContext,
});
