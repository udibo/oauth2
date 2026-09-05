import { Hono } from "hono";
import { logger } from "hono/logger";
import type { AppEnv } from "@udibo/juniper/server";

const app = new Hono<AppEnv>();

app.use(logger());

export default app;
