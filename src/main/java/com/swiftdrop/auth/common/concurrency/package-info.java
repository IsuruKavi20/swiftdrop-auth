/**
 * Shared building block, deliberately exposed to every feature module as the "concurrency" named interface.
 * Everything in common that is NOT exposed like this stays internal (checked by ModularityTest).
 */
@NamedInterface("concurrency")
package com.swiftdrop.auth.common.concurrency;

import org.springframework.modulith.NamedInterface;
