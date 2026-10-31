/**
 * Shared building block, deliberately exposed to every feature module as the "error" named interface.
 * Everything in common that is NOT exposed like this stays internal (checked by ModularityTest).
 */
@NamedInterface("error")
package com.swiftdrop.auth.common.error;

import org.springframework.modulith.NamedInterface;
