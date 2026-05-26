/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.token;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.UUID;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import eu.europa.esig.dss.DSSException;

/**
 * PKCS11 token with callback
 */
public class Pkcs11SignatureToken extends AbstractSignatureTokenConnection {

	private Provider _pkcs11Provider;

	private final String _pkcs11Path;

	private KeyStore _keyStore;

	private final PasswordInputCallback callback;

	private int slotIndex;

	/**
	 * Create the SignatureTokenConnection, using the provided path for the library.
	 *
	 * @param pkcs11Path
	 */
	public Pkcs11SignatureToken(String pkcs11Path) {
		this(pkcs11Path, (PasswordInputCallback) null);
	}

	/**
	 * Create the SignatureTokenConnection, using the provided path for the library and a way of retrieving the password
	 * from the user. The default constructor for CallbackPkcs11SignatureToken.
	 *
	 * @param pkcs11Path
	 * @param callback
	 */
	public Pkcs11SignatureToken(String pkcs11Path, PasswordInputCallback callback) {
		this._pkcs11Path = pkcs11Path;
		this.callback = callback;
		this.slotIndex = 0;
	}

	/**
	 * Sometimes, the password is known in advance. This create a SignatureTokenConnection and the keys will be accessed
	 * using the provided password. The default constructor for CallbackPkcs11SignatureToken.
	 *
	 * @param pkcs11Path
	 * @param password
	 */
	public Pkcs11SignatureToken(String pkcs11Path, char[] password) {
		this(pkcs11Path, new PrefilledPasswordCallback(password));
	}

	/**
	 * Sometimes, multiple SmartCard reader is connected. To create a connection on a specific one, slotIndex is used.
	 * This create a SignatureTokenConnection and the keys will be accessed using the provided password.
	 *
	 * @param pkcs11Path
	 * @param callback
	 * @param slotIndex
	 */
	public Pkcs11SignatureToken(String pkcs11Path, PasswordInputCallback callback, int slotIndex) {
		this(pkcs11Path, callback);
		this.slotIndex = slotIndex;
	}

	/**
	 * Sometimes, multiple SmartCard reader is connected. To create a connection on a specific one, slotIndex is used.
	 * This Create the SignatureTokenConnection, using the provided path for the library and a way of retrieving the
	 * password from the user.
	 *
	 * @param pkcs11Path
	 * @param password
	 * @param slotIndex
	 */
	public Pkcs11SignatureToken(String pkcs11Path, char[] password, int slotIndex) {
		this(pkcs11Path, password);
		this.slotIndex = slotIndex;
	}

	private Provider getProvider() {
		try {
			if (_pkcs11Provider == null) {
				// check if the provider already exists
				final Provider[] providers = Security.getProviders();
				if (providers != null) {
					for (final Provider provider : providers) {
						final String providerInfo = provider.getInfo();
						if (providerInfo.contains(getPkcs11Path())) {
							_pkcs11Provider = provider;
							return provider;
						}
					}
				}
				// provider not already installed

				installProvider();
			}
			return _pkcs11Provider;
		} catch (ProviderException ex) {
			throw new DSSException("Not a PKCS#11 library", ex);
		}
	}

	@SuppressWarnings("restriction")
	private void installProvider() {

		/*
		 * The smartCardNameIndex int is added at the end of the smartCard name in order to enable the successive
		 * loading of multiple pkcs11 libraries
		 */
		String aPKCS11LibraryFileName = getPkcs11Path();
		aPKCS11LibraryFileName = escapePath(aPKCS11LibraryFileName);

		String pkcs11ConfigSettings = "--name = SmartCard" + UUID.randomUUID().toString() + "\n" + "library = \"" + aPKCS11LibraryFileName
				+ "\"\nslotListIndex = " + slotIndex;

        try {
            if (getJavaMajorVersion() >= 9) {
                Provider provider = Security.getProvider("SunPKCS11");
                Method configureMethod = provider.getClass().getMethod("configure", String.class);
                _pkcs11Provider = (Provider) configureMethod.invoke(provider, pkcs11ConfigSettings);
            } else {
                Class<?> sunPkcs11ProviderClass = Class.forName("sun.security.pkcs11.SunPKCS11");
                Constructor<?> constructor = sunPkcs11ProviderClass.getConstructor(String.class);
                _pkcs11Provider = (Provider) constructor.newInstance(pkcs11ConfigSettings);
            }
		    Security.addProvider(_pkcs11Provider);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

	}

    private static int getJavaMajorVersion() {
        String version = System.getProperty("java.specification.version");
        if (version == null || version.equals("")) {
            version = System.getProperty("java.version");
        }
        if (version == null || version.equals("")) {
            return 0;
        }
        return parseMajor(version.trim());
    }

    private static int parseMajor(String version) {
        // "1.8" -> 8
        if (version.startsWith("1.")) {
            int dot = version.indexOf('.', 2);
            String majorPart = (dot > 0) ? version.substring(2, dot) : version.substring(2);
            return safeParseInt(majorPart);
        }

        // "9", "11", "17.0.2", "21-ea", "21+35"
        int end = 0;
        while (end < version.length() && Character.isDigit(version.charAt(end))) {
            end++;
        }
        if (end == 0) {
            return 0;
        }
        return safeParseInt(version.substring(0, end));
    }

    private static int safeParseInt(String value) {
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException ex) {
            return 0;
        }
    }

	private String escapePath(String pathToEscape) {
		if (pathToEscape != null) {
			return pathToEscape.replace("\\", "\\\\");
		} else {
			return "";
		}
	}

	@SuppressWarnings("restriction")
	private KeyStore getKeyStore() throws KeyStoreException {

		if (_keyStore == null) {
			_keyStore = KeyStore.getInstance("PKCS11", getProvider());
			try {
				_keyStore.load(new KeyStore.LoadStoreParameter() {

					@Override
					public ProtectionParameter getProtectionParameter() {
						return new KeyStore.CallbackHandlerProtection(new CallbackHandler() {

							@Override
							public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
								for (Callback c : callbacks) {
									if (c instanceof PasswordCallback) {
										((PasswordCallback) c).setPassword(callback.getPassword());
										return;
									}
								}
								throw new RuntimeException("No password callback");
							}
						});
					}
				});
			} catch (Exception e) {
                if ("sun.security.pkcs11.wrapper.PKCS11Exception".equals(e.getClass().getName())) {
					if ("CKR_PIN_INCORRECT".equals(e.getMessage())) {
						throw new DSSException("Bad password for PKCS11", e);
					}
				}
				throw new KeyStoreException("Can't initialize Sun PKCS#11 security provider. Reason: " + e.getMessage(), e);
			}
		}
		return _keyStore;
	}

	protected String getPkcs11Path() {
		return _pkcs11Path;
	}

	@Override
	public void close() {
		if (_pkcs11Provider != null) {
			try {
				Security.removeProvider(_pkcs11Provider.getName());
			} catch (Exception ex) {
				logger.error(ex.getMessage(), ex);
			}
		}
		this._pkcs11Provider = null;
		this._keyStore = null;
	}

	@Override
	public List<DSSPrivateKeyEntry> getKeys() throws DSSException {

		final List<DSSPrivateKeyEntry> list = new ArrayList<DSSPrivateKeyEntry>();

		try {
			final KeyStore keyStore = getKeyStore();
			final Enumeration<String> aliases = keyStore.aliases();
			while (aliases.hasMoreElements()) {
				final String alias = aliases.nextElement();
				if (keyStore.isKeyEntry(alias)) {
					final PrivateKeyEntry entry = (PrivateKeyEntry) keyStore.getEntry(alias, null);
					list.add(new KSPrivateKeyEntry(alias, entry));
				}
			}

		} catch (Exception e) {
			throw new DSSException("Can't initialize Sun PKCS#11 security " + "provider. Reason: " + e.getMessage(), e);
		}
		return list;
	}

}
