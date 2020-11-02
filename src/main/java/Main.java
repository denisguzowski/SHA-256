public class Main {
    public static void main(String[] args) {
        //Partial Hash Collision

        SHA256 sha256 = new SHA256();

        String text = "abcdefghijkmnopqrstuvwxyz";
        int count = 0;

        long start = System.currentTimeMillis();

        while (true) {
           String message = text + ":" + count;
           String hash = sha256.calc(message.getBytes());

           if (hash.startsWith("0000000")) {
               System.out.println(message);
               System.out.println(hash);
               break;
           }

           count++;
        }

        long finish = System.currentTimeMillis();
        long timeElapsed = finish - start;

        System.out.printf("%d ms or %f s%n", timeElapsed, timeElapsed / 1000d );
    }
}
