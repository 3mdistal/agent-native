import { defineEventHandler } from "h3";

import { handlePrivateVaultRotationEvidence } from "../../../../lib/private-vault-rotation-evidence-route.js";

export default defineEventHandler((event) =>
  handlePrivateVaultRotationEvidence(event, "offer"),
);
