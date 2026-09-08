import { Hono } from "hono";
import { requestLogger } from "@udibo/oauth2/hono/log";
import type { AppEnv } from "@udibo/juniper/server";

const app = new Hono<AppEnv>();

app.use(requestLogger());

export default app;
