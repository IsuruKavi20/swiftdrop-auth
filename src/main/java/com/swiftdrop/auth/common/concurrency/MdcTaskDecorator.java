package com.swiftdrop.auth.common.concurrency;

import org.slf4j.MDC;
import org.springframework.core.task.TaskDecorator;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Background tasks (e.g. sending an email after signup) run on other threads, where the request's MDC
 * (its requestId) is missing. This copies the submitting thread's MDC into the task and clears it after,
 * so background log lines can still be matched to the request. Spring Boot applies it to its task executor.
 */
@Component
public class MdcTaskDecorator implements TaskDecorator {

    @Override
    public Runnable decorate(Runnable task) {
        Map<String, String> context = MDC.getCopyOfContextMap();
        return () -> {
            if (context != null) {
                MDC.setContextMap(context);
            }
            try {
                task.run();
            } finally {
                MDC.clear();
            }
        };
    }
}
