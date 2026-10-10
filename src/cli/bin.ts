#!/usr/bin/env node
import { runCli } from "./mod.ts";

process.exitCode = await runCli(process.argv.slice(2));
