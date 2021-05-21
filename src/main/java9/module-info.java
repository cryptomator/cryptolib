module org.cryptomator.cryptolib {
	requires org.cryptomator.siv;
	requires com.google.gson;
	requires com.google.common;
	requires org.slf4j;

	exports org.cryptomator.cryptolib;
	exports org.cryptomator.cryptolib.api;
	exports org.cryptomator.cryptolib.common;

	opens org.cryptomator.cryptolib.common to com.google.gson;
}