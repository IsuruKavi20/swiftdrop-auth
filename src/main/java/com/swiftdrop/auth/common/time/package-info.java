/**
 * Shared building block, deliberately exposed to every feature module as the "time" named interface.
 * Everything in common that is NOT exposed like this stays internal (checked by ModularityTest).
 */
@NamedInterface("time")
package com.swiftdrop.auth.common.time;

import org.springframework.modulith.NamedInterface;
