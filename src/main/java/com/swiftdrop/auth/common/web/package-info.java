/**
 * Shared building block, deliberately exposed to every feature module as the "web" named interface.
 * Everything in common that is NOT exposed like this stays internal (checked by ModularityTest).
 */
@NamedInterface("web")
package com.swiftdrop.auth.common.web;

import org.springframework.modulith.NamedInterface;
