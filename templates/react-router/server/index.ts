/**
 * The server entry React Router builds into `build/server/index.js`: one Hono
 * app that runs the auth layer and hands every other request to React Router.
 *
 * @module
 */

import { createHonoServer } from "react-router-hono-server/node";

import auth from "./auth.ts";
import { config } from "./config.ts";
import { createLoadContext } from "./load-context.ts";

export default await createHonoServer({
  port: config.port,
  configure(app) {
    app.route("/", auth);
  },
  getLoadContext: createLoadContext,
});
