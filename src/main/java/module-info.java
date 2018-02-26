module org.cryptomator.cryptolib {
	exports org.cryptomator.cryptolib;
	exports org.cryptomator.cryptolib.api;
	exports org.cryptomator.cryptolib.common;

	opens org.cryptomator.cryptolib.api to gson;
	opens org.cryptomator.cryptolib.v1 to gson;

	requires org.cryptomator.siv;
	requires java.sql;
	requires gson;
	requires com.google.common;
	requires org.slf4j;
}