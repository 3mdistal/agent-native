import { defineEventHandler, getRouterParam } from "h3";

import { handlePrivateVaultRotationEvidenceExchange } from "../../../../../lib/private-vault-rotation-evidence-route.js";

export default defineEventHandler((event) =>
  handlePrivateVaultRotationEvidenceExchange(
    event,
    "status",
    getRouterParam(event, "ceremonyId") ?? "",
  ),
);
