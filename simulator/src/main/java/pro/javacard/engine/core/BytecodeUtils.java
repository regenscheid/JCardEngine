package pro.javacard.engine.core;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BytecodeUtils {
    private static final Logger log = LoggerFactory.getLogger(BytecodeUtils.class);

    public static byte[] transform(byte[] classBytes, ClassLoader classLoader) {

        ClassReader classReader = new ClassReader(classBytes);
        ClassWriter classWriter = new CustomClassWriter(classReader, ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES, classLoader);

        MemoryAllocationInterceptor interceptor = new MemoryAllocationInterceptor(classWriter);
        //classReader.accept(interceptor, 0);
        FaultInjectionInterceptor other = new FaultInjectionInterceptor(interceptor);
        classReader.accept(other, 0);

        return classWriter.toByteArray();
    }

    static class CustomClassWriter extends ClassWriter {
        private final ClassLoader classLoader;

        public CustomClassWriter(ClassReader classReader, int flags, ClassLoader classLoader) {
            super(classReader, flags);
            this.classLoader = classLoader == null ? super.getClassLoader() : classLoader;
        }

        @Override
        protected ClassLoader getClassLoader() {
            return classLoader;
        }

        @Override
        protected String getCommonSuperClass(String type1, String type2) {
            try {
                String s1 = type1;
                while (s1 != null) {
                    String s2 = type2;
                    while (s2 != null) {
                        if (s1.equals(s2)) {
                            return s1;
                        }
                        s2 = getSuperClassName(s2);
                    }
                    s1 = getSuperClassName(s1);
                }
            } catch (Exception e) {
                log.warn("Could not resolve common superclass for {} and {}: {}", type1, type2, e.getMessage());
            }
            return "java/lang/Object";
        }

        private String getSuperClassName(String internalName) throws Exception {
            if ("java/lang/Object".equals(internalName)) {
                return null;
            }
            var is = classLoader.getResourceAsStream(internalName + ".class");
            if (is == null) {
                return null;
            }
            try {
                return new ClassReader(is.readAllBytes()).getSuperName();
            } finally {
                is.close();
            }
        }
    }
}
