package livetesting;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Comparator;

public interface TestOrder {
    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    @interface Order {
        int value();
    }

    static Comparator<TestOrder.Order> comparator() {
        return (or1, or2) -> {
            if (or1 != null && or2 != null) {
                return or1.value() - or2.value();
            } else if (or1 != null) {
                return -1;
            } else if (or2 != null) {
                return 1;
            }
            return 0;
        };
    }
}
