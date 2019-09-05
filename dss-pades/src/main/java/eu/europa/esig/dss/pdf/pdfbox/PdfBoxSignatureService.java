/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 * <p>
 * This file is part of the "DSS - Digital Signature Services" project.
 * <p>
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * <p>
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * <p>
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package eu.europa.esig.dss.pdf.pdfbox;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import eu.europa.esig.dss.DSSUtils;
import eu.europa.esig.dss.DigestAlgorithm;
import eu.europa.esig.dss.pades.PAdESSignatureParameters;
import eu.europa.esig.dss.pades.SignatureImageParameters;
import eu.europa.esig.dss.pades.signature.visible.ImageAndResolution;
import eu.europa.esig.dss.pades.signature.visible.ImageUtils;
import eu.europa.esig.dss.pdf.DSSDictionaryCallback;
import eu.europa.esig.dss.pdf.PDFSignatureService;
import eu.europa.esig.dss.pdf.PdfDict;
import eu.europa.esig.dss.pdf.PdfDssDict;
import eu.europa.esig.dss.pdf.PdfSignatureInfo;
import eu.europa.esig.dss.pdf.PdfSignatureOrDocTimestampInfo;
import eu.europa.esig.dss.pdf.PdfSignatureOrDocTimestampInfoComparator;
import eu.europa.esig.dss.pdf.SignatureValidationCallback;
import eu.europa.esig.dss.utils.Utils;
import eu.europa.esig.dss.x509.CertificatePool;
import eu.europa.esig.dss.x509.CertificateToken;
import eu.europa.esig.dss.x509.Token;
import eu.europa.esig.dss.x509.crl.CRLToken;
import eu.europa.esig.dss.x509.ocsp.OCSPToken;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.COSArrayList;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationRubberStamp;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceDictionary;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAppearanceStream;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDPropBuild;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDPropBuildDataDict;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.util.Matrix;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.geom.AffineTransform;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

class PdfBoxSignatureService implements PDFSignatureService {

    private static final Logger logger = LoggerFactory.getLogger(PdfBoxSignatureService.class);

    @Override
    public byte[] digest(final InputStream toSignDocument, final PAdESSignatureParameters parameters, final DigestAlgorithm digestAlgorithm) throws DSSException {

        final byte[] signatureValue = DSSUtils.EMPTY_BYTE_ARRAY;
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        PDDocument pdDocument = null;
        try {
            pdDocument = PDDocument.load(toSignDocument, parameters.getPassword());
            PDSignature pdSignature = createSignatureDictionary(parameters, pdDocument);

            return signDocumentAndReturnDigest(parameters, signatureValue, outputStream, pdDocument, pdSignature, digestAlgorithm);
        } catch (IOException e) {
            throw new DSSException(e);
        } finally {
            Utils.closeQuietly(pdDocument);
            Utils.closeQuietly(outputStream);
        }
    }

    @Override
    public void sign(final InputStream pdfData, final byte[] signatureValue, final OutputStream signedStream, final PAdESSignatureParameters parameters, final DigestAlgorithm digestAlgorithm)
            throws DSSException {

        PDDocument pdDocument = null;
        try {
            pdDocument = PDDocument.load(pdfData, parameters.getPassword());
            final PDSignature pdSignature = createSignatureDictionary(parameters, pdDocument);
            signDocumentAndReturnDigest(parameters, signatureValue, signedStream, pdDocument, pdSignature, digestAlgorithm);
        } catch (IOException e) {
            throw new DSSException(e);
        } finally {
            Utils.closeQuietly(pdDocument);
        }
    }

    private byte[] signDocumentAndReturnDigest(final PAdESSignatureParameters pAdESSignatureParameters, final byte[] signatureBytes, final OutputStream fileOutputStream, final PDDocument pdDocument,
            final PDSignature pdSignature, final DigestAlgorithm digestAlgorithm) throws DSSException {

        SignatureOptions options = new SignatureOptions();
        try {

            final MessageDigest digest = DSSUtils.getMessageDigest(digestAlgorithm);
            // register signature dictionary and sign interface
            SignatureInterface signatureInterface = new SignatureInterface() {

                @Override
                public byte[] sign(InputStream content) throws IOException {

                    byte[] b = new byte[4096];
                    int count;
                    while ((count = content.read(b)) > 0) {
                        digest.update(b, 0, count);
                    }
                    return signatureBytes;
                }
            };

            options.setPreferredSignatureSize(pAdESSignatureParameters.getSignatureSize());
            PDVisibleSigProperties pdVisibleSigProperties = null;

            if (pAdESSignatureParameters.getImageParameters() != null) {
                pdVisibleSigProperties = fillImageParameters(pdDocument, pAdESSignatureParameters.getImageParameters(), options);
            }

            pdDocument.addSignature(pdSignature, signatureInterface, options);
            PDAcroForm acroForm = pdDocument.getDocumentCatalog().getAcroForm();

            // FIX Viafirma
            if (acroForm != null && acroForm.getNeedAppearances()) {
                // PDFBOX-3738 NeedAppearances true results in visible signature
                // becoming invisible
                acroForm.getCOSObject().removeItem(COSName.NEED_APPEARANCES);
            }
            if (pAdESSignatureParameters.getImageParameters() != null && pAdESSignatureParameters.getImageParameters().isInAllPages() && pdVisibleSigProperties != null) {
                stampSignedDocument(pdDocument, pAdESSignatureParameters, options, pdVisibleSigProperties, pAdESSignatureParameters.getImageParameters());
            }
            saveDocumentIncrementally(pAdESSignatureParameters, fileOutputStream, pdDocument);
            final byte[] digestValue = digest.digest();
            if (logger.isDebugEnabled()) {
                logger.debug("Digest to be signed: {}", Utils.toHex(digestValue));
            }
            return digestValue;
        } catch (IOException e) {
            throw new DSSException(e);
        } finally {
            Utils.closeQuietly(options.getVisualSignature());
        }
    }

    private void stampSignedDocument(PDDocument document, final PAdESSignatureParameters pAdESSignatureParameters, SignatureOptions signatureOptions, PDVisibleSigProperties pdVisibleSigProperties,
            SignatureImageParameters imageParameters) throws IOException {

        for (int i = 0; i < document.getNumberOfPages(); i++) {
            if (signatureOptions.getPage() != i) {
                PDPage page = document.getPage(i);
                List<PDAnnotation> annotations = page.getAnnotations();

                COSDictionary dict = page.getCOSObject();
                while (dict.containsKey(COSName.PARENT)) {
                    COSBase parent = dict.getDictionaryObject(COSName.PARENT);
                    if (parent instanceof COSDictionary) {
                        dict = (COSDictionary) parent;
                        dict.setNeedToBeUpdated(true);
                    }
                }

                ImageAndResolution ires = ImageUtils.create(pAdESSignatureParameters.getImageParameters());
                PDImageXObject pdImageXObject;
                try (InputStream is = ires.getInputStream()) {
                    pdImageXObject = PDImageXObject.createFromByteArray(document, IOUtils.toByteArray(is), pAdESSignatureParameters.getDeterministicId());
                }

                // stamp
                PDAnnotationRubberStamp stamp = new PDAnnotationRubberStamp();
                stamp.setName(pAdESSignatureParameters.getReason());
                stamp.setContents(null);
                stamp.setLocked(true);
                stamp.setReadOnly(true);
                stamp.setPrinted(true);

                Calendar calendar = Calendar.getInstance();
                calendar.setTime(pAdESSignatureParameters.getBLevelParams().getSigningDate());
                stamp.setCreationDate(calendar);
                stamp.setModifiedDate(calendar);

                PDVisibleSignDesigner signDesigner = pdVisibleSigProperties.getPdVisibleSignature();

                int pageRotation = page.getRotation();
                float width = signDesigner.getWidth();
                float height = signDesigner.getHeight();
                float pageWidth = page.getMediaBox().getWidth();
                float pageHeight = page.getMediaBox().getHeight();

                float stamperX;
                float stamperY;
                if (pageRotation == 90) {
                    stamperX = imageParameters.getyAxis();
                    stamperY = -imageParameters.getxAxis();
                } else if (pageRotation == 270) {
                    stamperX = -imageParameters.getyAxis();
                    stamperY = imageParameters.getxAxis();
                } else {
                    stamperX = imageParameters.getxAxis();
                    stamperY = imageParameters.getyAxis();
                }

                // Uses negative position for inverted axis origin
                float x = stamperX < 0 ? pageWidth - width + stamperX : stamperX;
                float y = stamperY < 0 ? -stamperY : pageHeight - height - stamperY;

                PDRectangle rectangle = new PDRectangle(x, y, width, height);
                PDFormXObject form = new PDFormXObject(document);
                form.setResources(new PDResources());
                form.setBBox(rectangle);
                form.setFormType(1);

                form.getResources().getCOSObject().setNeedToBeUpdated(true);
                form.getResources().add(pdImageXObject);
                PDAppearanceStream appearanceStream = new PDAppearanceStream(form.getCOSObject());
                PDAppearanceDictionary appearance = new PDAppearanceDictionary(new COSDictionary());
                appearance.setNormalAppearance(appearanceStream);
                stamp.setAppearance(appearance);
                stamp.setRectangle(rectangle);
                PDPageContentStream stream = new PDPageContentStream(document, appearanceStream);

                AffineTransform affineTransform;
                if (pageRotation == 90) {
                    affineTransform = new AffineTransform(0, height, -width, 0, x + width, y);
                } else if (pageRotation == 270) {
                    affineTransform = new AffineTransform(0, -height, width, 0, x, y + height);
                } else {
                    affineTransform = new AffineTransform(width, 0, 0, height, x, y);
                }
                stream.drawImage(pdImageXObject, new Matrix(affineTransform));

                stream.close();
                // close and save
                annotations.add(stamp);

                appearanceStream.getCOSObject().setNeedToBeUpdated(true);
                appearance.getCOSObject().setNeedToBeUpdated(true);
                rectangle.getCOSArray().setNeedToBeUpdated(true);
                stamp.getCOSObject().setNeedToBeUpdated(true);
                form.getCOSObject().setNeedToBeUpdated(true);
                COSArrayList<PDAnnotation> list = (COSArrayList<PDAnnotation>) annotations;
                COSArrayList.converterToCOSArray(list).setNeedToBeUpdated(true);
                document.getPages().getCOSObject().setNeedToBeUpdated(true);
                page.getCOSObject().setNeedToBeUpdated(true);
                document.getDocumentCatalog().getCOSObject().setNeedToBeUpdated(true);
            }
        }

    }

    private PDVisibleSigProperties fillImageParameters(final PDDocument pdDocument, final SignatureImageParameters signatureImageParameters, SignatureOptions signatureOptions) throws IOException {

        // DSS-747. Using the DPI resolution to convert java size to dot
        ImageAndResolution ires = ImageUtils.create(signatureImageParameters);

        InputStream is = ires.getInputStream();
        try {
            PDVisibleSignDesigner pdVisibleSignDesigner = new PDVisibleSignDesigner(pdDocument, is, signatureImageParameters.getPage());

            int pageRotation = pdDocument.getPage(signatureOptions.getPage()).getRotation();
            float stamperX;
            float stamperY;
            float width;
            float height;
            float pageWidth = pdVisibleSignDesigner.getPageWidth();
            float pageHeight = pdVisibleSignDesigner.getPageHeight();

            if (pageRotation == 90) {
                stamperX = signatureImageParameters.getyAxis();
                stamperY = -signatureImageParameters.getxAxis();
                width = ires.toXPoint(pdVisibleSignDesigner.getHeight());
                height = ires.toXPoint(pdVisibleSignDesigner.getWidth());
            } else if (pageRotation == 270) {
                stamperX = -signatureImageParameters.getyAxis();
                stamperY = signatureImageParameters.getxAxis();
                width = ires.toXPoint(pdVisibleSignDesigner.getHeight());
                height = ires.toXPoint(pdVisibleSignDesigner.getWidth());
            } else {
                stamperX = signatureImageParameters.getxAxis();
                stamperY = signatureImageParameters.getyAxis();
                width = ires.toXPoint(pdVisibleSignDesigner.getWidth());
                height = ires.toXPoint(pdVisibleSignDesigner.getHeight());
            }

            // Uses negative position for inverted axis origin
            float x = stamperX < 0 ? pageWidth - width + stamperX : stamperX;
            float y = stamperY < 0 ? pageHeight - height + stamperY : stamperY;

            pdVisibleSignDesigner.xAxis(x).yAxis(y);
            pdVisibleSignDesigner.width(width).height(height);

            AffineTransform affineTransform;
            if (pageRotation == 90) {
                affineTransform = new AffineTransform(0, height / width, -width / height, 0, width, 0);
            } else if (pageRotation == 270) {
                affineTransform = new AffineTransform(0, -height / width, width / height, 0, 0, height);
            } else {
                affineTransform = new AffineTransform();
            }

            pdVisibleSignDesigner.transform(affineTransform);
            pdVisibleSignDesigner.zoom(signatureImageParameters.getZoom() - 100f); // pdfbox is 0 based

            PDVisibleSigProperties pdVisibleSigProperties = new PDVisibleSigProperties();
            pdVisibleSigProperties.visualSignEnabled(true).setPdVisibleSignature(pdVisibleSignDesigner).buildSignature();

            signatureOptions.setVisualSignature(pdVisibleSigProperties);
            signatureOptions.setPage(signatureImageParameters.getPage() - 1); // DSS-1138

            return pdVisibleSigProperties;
        } finally {
            Utils.closeQuietly(is);
        }
    }

    private void addCertificationLevel(final PAdESSignatureParameters parameters, PDDocument doc, final PDSignature signature) {

        // DocMDP thing
        COSDictionary dictionary = signature.getCOSObject();

        //Create Permissions Dictionary
        COSDictionary permissions = new COSDictionary();
        permissions.setItem("DocMDP", signature);

        //Add Permissions to Catalog
        COSDictionary catalog = doc.getDocumentCatalog().getCOSObject();
        catalog.setItem("Perms", permissions);
        // Create a reference dictionary
        COSDictionary reference = new COSDictionary();
        reference.setItem("Type", COSName.getPDFName("SigRef"));
        reference.setItem("TransformMethod", COSName.getPDFName("DocMDP"));
        reference.setItem("DigestMethod", COSName.getPDFName("SHA1"));

        // Now we add DocMDP specific stuff
        COSDictionary transformParameters = new COSDictionary();
        transformParameters.setItem("Type", COSName.getPDFName("TransformParams"));
        transformParameters.setInt("P", parameters.getCertifiedLevel().getValue()); //
        transformParameters.setItem("V", COSName.getPDFName("1.2"));
        // Add everything in order
        reference.setItem("TransformParams", transformParameters);
        COSArray references = new COSArray();
        references.add(reference); // Add SigRef Dictionary to a Array
        dictionary.setItem("Reference", references); // Add Array to Signature dictionary
    }

    private PDSignature createSignatureDictionary(final PAdESSignatureParameters parameters, PDDocument doc) {

        final PDSignature signature = new PDSignature();
        signature.setType(getType());

        Date date = parameters.bLevel().getSigningDate();
        String encodedDate = " " + Utils.toHex(DSSUtils.digest(DigestAlgorithm.SHA1, Long.toString(date.getTime()).getBytes()));
        CertificateToken token = parameters.getSigningCertificate();
        if (token == null) {
            signature.setName("Unknown signer" + encodedDate);
        } else {
            signature.setName(DSSUtils.getDeterministicId(date, token.getDSSId()) + "##" + parameters.getCustomId());
        }

        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE); // default filter
        // sub-filter for basic and PAdES Part 2 signatures
        signature.setSubFilter(getSubFilter());

        if (COSName.SIG.equals(getType())) {
            if (Utils.isStringNotEmpty(parameters.getContactInfo())) {
                signature.setContactInfo(parameters.getContactInfo());
            }

            if (Utils.isStringNotEmpty(parameters.getLocation())) {
                signature.setLocation(parameters.getLocation());
            }

            if (Utils.isStringNotEmpty(parameters.getReason())) {
                signature.setReason(parameters.getReason());
            }

            PDPropBuild pb = new PDPropBuild();
            PDPropBuildDataDict pd = new PDPropBuildDataDict();

            if (Utils.isStringNotEmpty(parameters.getSoftwareName())) {
                pd.setName(parameters.getSoftwareName());
                pb.setPDPropBuildApp(pd);
                signature.setPropBuild(pb);
            }

            if (Utils.isStringNotEmpty(parameters.getSoftwareVersion())) {
                pd.setVersion(parameters.getSoftwareVersion());
                pb.setPDPropBuildApp(pd);
                signature.setPropBuild(pb);
            }

        }

        try {
            List<PDSignature> pdSignatures = doc.getSignatureDictionaries();
            if (parameters.getCertifiedLevel() != null && (pdSignatures == null || pdSignatures.isEmpty())) {
                addCertificationLevel(parameters, doc, signature);
            }
        } catch (IOException e) {
            throw new DSSException(e);
        }

        // the signing date, needed for valid signature
        final Calendar cal = Calendar.getInstance();
        final Date signingDate = parameters.bLevel().getSigningDate();
        cal.setTime(signingDate);
        signature.setSignDate(cal);
        return signature;
    }

    protected COSName getType() {
        return COSName.SIG;
    }

    public void saveDocumentIncrementally(PAdESSignatureParameters parameters, OutputStream outputStream, PDDocument pdDocument) throws DSSException {
        try {
            // the document needs to have an ID, if not a ID based on the
            // current system time is used, and then the
            // digest of the signed data is
            // different
            if (pdDocument.getDocumentId() == null) {

                final byte[] documentIdBytes = DSSUtils.digest(DigestAlgorithm.MD5, parameters.bLevel().getSigningDate().toString().getBytes());
                pdDocument.setDocumentId(DSSUtils.toLong(documentIdBytes));
                pdDocument.setDocumentId(0L);
            }
            pdDocument.saveIncremental(outputStream);
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }

    protected COSName getSubFilter() {
        return PDSignature.SUBFILTER_ETSI_CADES_DETACHED;
    }

    @Override
    public void validateSignatures(CertificatePool validationCertPool, DSSDocument document, SignatureValidationCallback callback) throws DSSException {
        // recursive search of signature
        InputStream inputStream = document.openStream();
        String password = document.getPassword();
        try {
            List<PdfSignatureOrDocTimestampInfo> signaturesFound = getSignatures(validationCertPool, Utils.toByteArray(inputStream), password);
            for (PdfSignatureOrDocTimestampInfo pdfSignatureOrDocTimestampInfo : signaturesFound) {
                callback.validate(pdfSignatureOrDocTimestampInfo);
            }
        } catch (IOException e) {
            logger.error("Cannot validate signatures : " + e.getMessage(), e);
        }

        Utils.closeQuietly(inputStream);
    }

    private List<PdfSignatureOrDocTimestampInfo> getSignatures(CertificatePool validationCertPool, byte[] originalBytes, String password) {
        List<PdfSignatureOrDocTimestampInfo> signatures = new ArrayList<>();
        PDDocument doc = null;
        try {
            doc = PDDocument.load(originalBytes, password);

            List<PDSignature> pdSignatures = doc.getSignatureDictionaries();
            if (Utils.isCollectionNotEmpty(pdSignatures)) {
                logger.debug("{} signature(s) found", pdSignatures.size());

                PdfDict catalog = new PdfBoxDict(doc.getDocumentCatalog().getCOSObject(), doc);
                PdfDssDict dssDictionary = PdfDssDict.extract(catalog);

                for (PDSignature signature : pdSignatures) {
                    String subFilter = signature.getSubFilter();
                    byte[] cms = signature.getContents(originalBytes);

                    if (Utils.isStringEmpty(subFilter) || Utils.isArrayEmpty(cms)) {
                        logger.warn("Wrong signature with empty subfilter or cms.");
                        continue;
                    }

                    byte[] signedContent = signature.getSignedContent(originalBytes);
                    int[] byteRange = signature.getByteRange();

                    PdfSignatureOrDocTimestampInfo signatureInfo;
                    if (PdfBoxDocTimeStampService.SUB_FILTER_ETSI_RFC3161.getName().equals(subFilter)) {
                        boolean isArchiveTimestamp = false;

                        // LT or LTA
                        if (dssDictionary != null) {
                            // check is DSS dictionary already exist
                            if (isDSSDictionaryPresentInPreviousRevision(getOriginalBytes(byteRange, signedContent), password)) {
                                isArchiveTimestamp = true;
                            }
                        }

                        signatureInfo = new PdfBoxDocTimestampInfo(validationCertPool, signature, dssDictionary, cms, signedContent, isArchiveTimestamp);
                    } else {
                        signatureInfo = new PdfBoxSignatureInfo(validationCertPool, signature, dssDictionary, cms, signedContent);
                    }

                    signatures.add(signatureInfo);
                }
                Collections.sort(signatures, new PdfSignatureOrDocTimestampInfoComparator());
                linkSignatures(signatures);

                for (PdfSignatureOrDocTimestampInfo sig : signatures) {
                    logger.debug("Signature " + sig.uniqueId() + " found with byteRange " + Arrays.toString(sig.getSignatureByteRange()) + " (" + sig.getSubFilter() + ")");
                }
            }

        } catch (Exception e) {
            logger.warn("Cannot analyze signatures : " + e.getMessage(), e);
        } finally {
            Utils.closeQuietly(doc);
        }

        return signatures;
    }

    /**
     * This method links previous signatures to the new one. This is useful to
     * get revision number and to know if a TSP is over the DSS dictionary
     */
    private void linkSignatures(List<PdfSignatureOrDocTimestampInfo> signatures) {
        List<PdfSignatureOrDocTimestampInfo> previousList = new ArrayList<>();
        for (PdfSignatureOrDocTimestampInfo sig : signatures) {
            if (Utils.isCollectionNotEmpty(previousList)) {
                for (PdfSignatureOrDocTimestampInfo previous : previousList) {
                    previous.addOuterSignature(sig);
                }
            }
            previousList.add(sig);
        }
    }

    private boolean isDSSDictionaryPresentInPreviousRevision(byte[] originalBytes, String password) {
        PDDocument doc = null;
        PdfDssDict dssDictionary = null;
        try {
            doc = PDDocument.load(originalBytes, password);
            List<PDSignature> pdSignatures = doc.getSignatureDictionaries();
            if (Utils.isCollectionNotEmpty(pdSignatures)) {
                PdfDict catalog = new PdfBoxDict(doc.getDocumentCatalog().getCOSObject(), doc);
                dssDictionary = PdfDssDict.extract(catalog);
            }
        } catch (Exception e) {
            logger.warn("Cannot check in previous revisions if DSS dictionary already exist : " + e.getMessage(), e);
        } finally {
            Utils.closeQuietly(doc);
        }

        return dssDictionary != null;
    }

    private byte[] getOriginalBytes(int[] byteRange, byte[] signedContent) {
        final int length = byteRange[1];
        final byte[] result = new byte[length];
        System.arraycopy(signedContent, 0, result, 0, length);
        return result;
    }

    @Override
    public void addDssDictionary(InputStream inputStream, OutputStream outputStream, List<DSSDictionaryCallback> callbacks, final PAdESSignatureParameters parameters) {
        PDDocument pdDocument = null;
        try {
            pdDocument = PDDocument.load(inputStream, parameters.getPassword());
            if (Utils.isCollectionNotEmpty(callbacks)) {
                final COSDictionary cosDictionary = pdDocument.getDocumentCatalog().getCOSObject();
                cosDictionary.setItem("DSS", buildDSSDictionary(callbacks));
                cosDictionary.setNeedToBeUpdated(true);
            }

            if (pdDocument.getDocumentId() == null) {
                pdDocument.setDocumentId(0L);
            }
            pdDocument.saveIncremental(outputStream);

        } catch (Exception e) {
            throw new DSSException(e);
        } finally {
            Utils.closeQuietly(pdDocument);
        }
    }

    private COSDictionary buildDSSDictionary(List<DSSDictionaryCallback> callbacks) throws Exception {
        COSDictionary dss = new COSDictionary();

        Map<String, COSStream> streams = new HashMap<>();

        Set<CRLToken> allCrls = new HashSet<>();
        Set<OCSPToken> allOcsps = new HashSet<>();
        Set<CertificateToken> allCertificates = new HashSet<>();

        COSDictionary vriDictionary = new COSDictionary();
        for (DSSDictionaryCallback callback : callbacks) {
            COSDictionary sigVriDictionary = new COSDictionary();
            sigVriDictionary.setDirect(true);

            if (Utils.isCollectionNotEmpty(callback.getCertificates())) {
                COSArray vriCertArray = new COSArray();
                for (CertificateToken token : callback.getCertificates()) {
                    vriCertArray.add(getStream(streams, token));
                    allCertificates.add(token);
                }
                sigVriDictionary.setItem("Cert", vriCertArray);
            }

            if (Utils.isCollectionNotEmpty(callback.getOcsps())) {
                COSArray vriOcspArray = new COSArray();
                for (OCSPToken token : callback.getOcsps()) {
                    vriOcspArray.add(getStream(streams, token));
                    allOcsps.add(token);
                }
                sigVriDictionary.setItem("OCSP", vriOcspArray);
            }

            if (Utils.isCollectionNotEmpty(callback.getCrls())) {
                COSArray vriCrlArray = new COSArray();
                for (CRLToken token : callback.getCrls()) {
                    vriCrlArray.add(getStream(streams, token));
                    allCrls.add(token);
                }
                sigVriDictionary.setItem("CRL", vriCrlArray);
            }

            // We can't use CMSSignedData, the pdSignature content is trimmed
            // (000000)
            PdfSignatureInfo pdfSignatureInfo = callback.getSignature().getPdfSignatureInfo();
            final byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, pdfSignatureInfo.getContent());
            String hexHash = Utils.toHex(digest).toUpperCase();

            vriDictionary.setItem(hexHash, sigVriDictionary);
        }
        dss.setItem("VRI", vriDictionary);

        if (Utils.isCollectionNotEmpty(allCertificates)) {
            COSArray arrayAllCerts = new COSArray();
            for (CertificateToken token : allCertificates) {
                arrayAllCerts.add(getStream(streams, token));
            }
            dss.setItem("Certs", arrayAllCerts);
        }

        if (Utils.isCollectionNotEmpty(allOcsps)) {
            COSArray arrayAllOcsps = new COSArray();
            for (OCSPToken token : allOcsps) {
                arrayAllOcsps.add(getStream(streams, token));
            }
            dss.setItem("OCSPs", arrayAllOcsps);
        }

        if (Utils.isCollectionNotEmpty(allCrls)) {
            COSArray arrayAllCrls = new COSArray();
            for (CRLToken token : allCrls) {
                arrayAllCrls.add(getStream(streams, token));
            }
            dss.setItem("CRLs", arrayAllCrls);
        }

        return dss;
    }

    private COSStream getStream(Map<String, COSStream> streams, Token token) throws IOException {
        COSStream stream = streams.get(token.getDSSIdAsString());
        if (stream == null) {
            stream = new COSStream();
            OutputStream unfilteredStream = stream.createOutputStream();
            unfilteredStream.write(token.getEncoded());
            unfilteredStream.flush();
            unfilteredStream.close();
            streams.put(token.getDSSIdAsString(), stream);
        }
        return stream;
    }
}
