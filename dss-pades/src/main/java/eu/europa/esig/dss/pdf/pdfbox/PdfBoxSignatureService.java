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
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.io.RandomAccessReadBuffer;
import org.apache.pdfbox.util.DateConverter;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageContentStream;
import org.apache.pdfbox.pdmodel.PDResources;
import org.apache.pdfbox.pdmodel.common.COSArrayList;
import org.apache.pdfbox.pdmodel.common.PDRectangle;
import org.apache.pdfbox.pdmodel.common.PDStream;
import org.apache.pdfbox.pdmodel.graphics.form.PDFormXObject;
import org.apache.pdfbox.pdmodel.graphics.image.PDImageXObject;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionURI;
import org.apache.pdfbox.pdmodel.interactive.annotation.*;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.*;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.apache.pdfbox.util.Matrix;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cms.CMSAbsentContent;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Base64Encoder;
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
            pdDocument = Loader.loadPDF(new RandomAccessReadBuffer(toSignDocument), parameters.getPassword());
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
            pdDocument = Loader.loadPDF(new RandomAccessReadBuffer(pdfData), parameters.getPassword());
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
            byte[] digestValue = null;

            PDVisibleSigProperties pdVisibleSigProperties = null;

            if (pAdESSignatureParameters.getImageParameters() != null) {
                pdVisibleSigProperties = fillImageParameters(pdDocument, pAdESSignatureParameters.getImageParameters(), options);
            }

            if (pAdESSignatureParameters.isExternalPkcs7Signature()){

                if (pdDocument.getDocumentId() == null) {
                    final byte[] documentIdBytes = DSSUtils.digest(DigestAlgorithm.MD5, pAdESSignatureParameters.bLevel().getSigningDate().toString().getBytes());
                    pdDocument.setDocumentId(DSSUtils.toLong(documentIdBytes));
                }

                options.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 10);
                pdDocument.addSignature(pdSignature, options);

                // Apply acroform and visual fixes BEFORE saveIncrementalForExternalSigning
                // so they are included in the signed content
                applyPreSaveFixes(pdDocument, pAdESSignatureParameters, options, pdVisibleSigProperties);

                ExternalSigningSupport externalSigning = pdDocument.saveIncrementalForExternalSigning(fileOutputStream);
                byte[] dataToSign = IOUtils.toByteArray(externalSigning.getContent());
                if (signatureBytes != null && signatureBytes.length > 0) {
                    externalSigning.setSignature(signatureBytes);
                }

                digest.update(dataToSign);

            } else {

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
                pdDocument.addSignature(pdSignature, signatureInterface, options);

                applyPreSaveFixes(pdDocument, pAdESSignatureParameters, options, pdVisibleSigProperties);

                saveDocumentIncrementally(pAdESSignatureParameters, fileOutputStream, pdDocument);
            }

            digestValue = digest.digest();
            if (logger.isDebugEnabled()) {
                logger.debug("Digest to be signed: {}", Base64.toBase64String(digestValue));
            }
            return digestValue;
        } catch (IOException e) {
            throw new DSSException(e);
        } finally {
            Utils.closeQuietly(options.getVisualSignature());
        }
    }

    // Applies acroform NeedAppearances fix and visual stamp/link before the document is saved.
    // Must be called BEFORE saveIncrementalForExternalSigning or saveDocumentIncrementally.
    private void applyPreSaveFixes(PDDocument pdDocument, PAdESSignatureParameters pAdESSignatureParameters,
                                   SignatureOptions options, PDVisibleSigProperties pdVisibleSigProperties) throws IOException {
        PDAcroForm acroForm = pdDocument.getDocumentCatalog().getAcroForm();
        // PDFBOX-3738: NeedAppearances true results in visible signature becoming invisible
        if (acroForm != null && acroForm.getNeedAppearances()) {
            acroForm.getCOSObject().removeItem(COSName.NEED_APPEARANCES);
        }

        if (pAdESSignatureParameters.getImageParameters() != null
                && pAdESSignatureParameters.getImageParameters().isInAllPages()
                && pdVisibleSigProperties != null
                && pdDocument.getNumberOfPages() > 1) {
            stampSignedDocument(pdDocument, pAdESSignatureParameters, options, pdVisibleSigProperties, pAdESSignatureParameters.getImageParameters());
        } else if (pAdESSignatureParameters.getImageParameters() != null && pAdESSignatureParameters.getLink() != null && pdVisibleSigProperties != null) {
            addLink(pdDocument, pAdESSignatureParameters, options, pdVisibleSigProperties, pAdESSignatureParameters.getImageParameters());
        }
    }

    private void stampSignedDocument(PDDocument document, final PAdESSignatureParameters pAdESSignatureParameters, SignatureOptions signatureOptions, PDVisibleSigProperties pdVisibleSigProperties, SignatureImageParameters imageParameters) throws IOException {

        ImageAndResolution ires = ImageUtils.create(pAdESSignatureParameters.getImageParameters());
        PDImageXObject pdImageXObject;
        try (InputStream is = ires.getInputStream()) {
            pdImageXObject = PDImageXObject.createFromByteArray(document, IOUtils.toByteArray(is), pAdESSignatureParameters.getDeterministicId());
        }

        // Hoist: PDPageTree.get(int) is O(n) — computing once avoids O(n²) in the loop
        PDVisibleSignDesigner signDesigner = pdVisibleSigProperties.getPdVisibleSignature();
        int signDesignerRotation = document.getPage(signatureOptions.getPage()).getRotation();

        Calendar calendar = Calendar.getInstance();
        calendar.setTime(pAdESSignatureParameters.getBLevelParams().getSigningDate());
        // Pre-compute once: DateConverter.toString() clones the Calendar internally on every call
        String precomputedDateStr = DateConverter.toString(calendar);

        // The same annotation object can appear in multiple pages' /Annots arrays (PDF spec allows it).
        // Key: rotation + page dimensions — uniquely determines x, y, width, height.
        // For a uniform document (all pages same size/rotation) this produces exactly 1 annotation,
        // 1 form XObject and 1 image in the incremental update instead of N copies.
        Map<String, PDAnnotationRubberStamp> stampCache = new HashMap<>();
        Map<String, PDAnnotationLink> linkCache = new HashMap<>();

        // Iterate via PDPageTree iterator (O(1) per page) instead of getPage(int) (O(n) per page)
        for (PDPage page : document.getPages()) {
            List<PDAnnotation> annotations = page.getAnnotations();

            COSDictionary dict = page.getCOSObject();
            while (dict.containsKey(COSName.PARENT)) {
                COSBase parent = dict.getDictionaryObject(COSName.PARENT);
                if (parent instanceof COSDictionary) {
                    dict = (COSDictionary) parent;
                    dict.setNeedToBeUpdated(true);
                }
            }

            int pageRotation = page.getRotation();

            float width = signDesigner.getWidth();
            float height = signDesigner.getHeight();
            if (signDesignerRotation == 0 && (pageRotation == 90 || pageRotation == 270)) {
                float temp = width;
                width = height;
                height = temp;
            }

            PDRectangle mediaBox = page.getMediaBox();
            float pageWidth = mediaBox.getWidth();
            float pageHeight = mediaBox.getHeight();

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

            String geometryKey = pageRotation + "_" + pageWidth + "_" + pageHeight;

            PDAnnotationRubberStamp stamp = stampCache.get(geometryKey);
            if (stamp == null) {
                PDFormXObject form = new PDFormXObject(document);
                PDResources resources = new PDResources();
                form.setResources(resources);
                form.setBBox(new PDRectangle(x, y, width, height));
                form.setFormType(1);
                resources.getCOSObject().setNeedToBeUpdated(true);
                resources.add(pdImageXObject);
                PDAppearanceStream appearanceStream = new PDAppearanceStream(form.getCOSObject());

                AffineTransform affineTransform;
                if (pageRotation == 90) {
                    affineTransform = new AffineTransform(0, height, -width, 0, x + width, y);
                } else if (pageRotation == 270) {
                    affineTransform = new AffineTransform(0, -height, width, 0, x, y + height);
                } else {
                    affineTransform = new AffineTransform(width, 0, 0, height, x, y);
                }
                try (PDPageContentStream contentStream = new PDPageContentStream(document, appearanceStream)) {
                    contentStream.drawImage(pdImageXObject, new Matrix(affineTransform));
                }
                form.getCOSObject().setNeedToBeUpdated(true);
                appearanceStream.getCOSObject().setNeedToBeUpdated(true);

                stamp = new PDAnnotationRubberStamp();
                stamp.setName(pAdESSignatureParameters.getReason());
                stamp.setContents(null);
                stamp.setLocked(true);
                stamp.setReadOnly(true);
                stamp.setPrinted(true);
                stamp.getCOSObject().setString(COSName.CREATION_DATE, precomputedDateStr);
                stamp.getCOSObject().setString(COSName.M, precomputedDateStr);

                PDAppearanceDictionary appearance = new PDAppearanceDictionary(new COSDictionary());
                appearance.setNormalAppearance(appearanceStream);
                stamp.setAppearance(appearance);
                stamp.setRectangle(new PDRectangle(x, y, width, height));

                appearance.getCOSObject().setNeedToBeUpdated(true);
                stamp.getCOSObject().setNeedToBeUpdated(true);

                stampCache.put(geometryKey, stamp);
            }

            annotations.add(stamp);

            if (pAdESSignatureParameters.getLink() != null) {
                PDAnnotationLink link = linkCache.get(geometryKey);
                if (link == null) {
                    PDActionURI action = new PDActionURI();
                    action.setURI(pAdESSignatureParameters.getLink());
                    link = new PDAnnotationLink();
                    link.setRectangle(new PDRectangle(x, y, width, height));
                    link.setAction(action);
                    link.getCOSObject().setNeedToBeUpdated(true);
                    linkCache.put(geometryKey, link);
                }
                annotations.add(link);
            }

            COSArrayList<PDAnnotation> list = (COSArrayList<PDAnnotation>) annotations;
            COSArrayList.converterToCOSArray(list).setNeedToBeUpdated(true);
            document.getPages().getCOSObject().setNeedToBeUpdated(true);
            page.getCOSObject().setNeedToBeUpdated(true);
            document.getDocumentCatalog().getCOSObject().setNeedToBeUpdated(true);
        }
        //}
    }

    /**
     * https://github.com/mkl-public/testarea-pdfbox2/blob/master/src/test/java/mkl/testarea/pdfbox2/sign/CreateMultipleVisualizations.java#L130
     */
    private void addImageOnlySignatureField(PDDocument pdDocument, PDPage pdPage, PDRectangle rectangle, PDSignature signature, PDImageXObject pdImage) throws IOException {
        PDAcroForm acroForm = pdDocument.getDocumentCatalog().getAcroForm();
        List<PDField> acroFormFields = acroForm.getFields();

        PDSignatureField signatureField = new PDSignatureField(acroForm);
        signatureField.setValue(signature);
        PDAnnotationWidget widget = signatureField.getWidgets().get(0);
        acroFormFields.add(signatureField);

        widget.setRectangle(rectangle);
        widget.setPage(pdPage);

        // from PDVisualSigBuilder.createHolderForm()
        PDStream stream = new PDStream(pdDocument);
        PDFormXObject form = new PDFormXObject(stream);
        PDResources res = new PDResources();
        form.setResources(res);
        form.setFormType(1);
        PDRectangle bbox = new PDRectangle(rectangle.getWidth(), rectangle.getHeight());

        form.setBBox(bbox);

        // from PDVisualSigBuilder.createAppearanceDictionary()
        PDAppearanceDictionary appearance = new PDAppearanceDictionary();
        appearance.getCOSObject().setDirect(true);
        PDAppearanceStream appearanceStream = new PDAppearanceStream(form.getCOSObject());
        appearance.setNormalAppearance(appearanceStream);
        widget.setAppearance(appearance);

        try (   PDPageContentStream cs = new PDPageContentStream(pdDocument, appearanceStream)) {
            cs.addComment("This is a comment");
            cs.drawImage(pdImage, 0, 0, rectangle.getWidth(), rectangle.getHeight());
        }

        pdPage.getAnnotations().add(widget);

        COSDictionary pageTreeObject = pdPage.getCOSObject();
        while (pageTreeObject != null) {
            pageTreeObject.setNeedToBeUpdated(true);
            pageTreeObject = (COSDictionary) pageTreeObject.getDictionaryObject(COSName.PARENT);
        }
    }

    private PDRectangle createSignatureRectangle(PDVisibleSigProperties pdVisibleSigProperties, SignatureImageParameters imageParameters, PDPage page){

        PDVisibleSignDesigner signDesigner = pdVisibleSigProperties.getPdVisibleSignature();

        int signDesignerRotation = page.getRotation();
        int pageRotation = page.getRotation();

        float width = signDesigner.getWidth();
        float height = signDesigner.getHeight();
        if (signDesignerRotation == 0 && (pageRotation == 90 || pageRotation == 270)) {
            float temp = width;
            width = height;
            height = temp;
        }

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

        return new PDRectangle(x, y, width, height);
    }

    private void addLink(PDDocument document, final PAdESSignatureParameters pAdESSignatureParameters, SignatureOptions signatureOptions, PDVisibleSigProperties pdVisibleSigProperties,
                                     SignatureImageParameters imageParameters) throws IOException {
        if(imageParameters.getPage()>0) {
            PDPage page = document.getPage(imageParameters.getPage() - 1);
            List<PDAnnotation> annotations = page.getAnnotations();

            COSDictionary dict = page.getCOSObject();
            while (dict.containsKey(COSName.PARENT)) {
                COSBase parent = dict.getDictionaryObject(COSName.PARENT);
                if (parent instanceof COSDictionary) {
                    dict = (COSDictionary) parent;
                    dict.setNeedToBeUpdated(true);
                }
            }

            // link
            PDAnnotationLink link = new PDAnnotationLink();

            // add an action
            PDActionURI action = new PDActionURI();
            action.setURI(pAdESSignatureParameters.getLink());
            link.setAction(action);

            PDVisibleSignDesigner signDesigner = pdVisibleSigProperties.getPdVisibleSignature();

            int signDesignerRotation = document.getPage(signatureOptions.getPage()).getRotation();
            int pageRotation = page.getRotation();

            float width = signDesigner.getWidth();
            float height = signDesigner.getHeight();
            if (signDesignerRotation == 0 && (pageRotation == 90 || pageRotation == 270)) {
                float temp = width;
                width = height;
                height = temp;
            }

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
            PDAppearanceStream appearanceStream = new PDAppearanceStream(form.getCOSObject());
            PDAppearanceDictionary appearance = new PDAppearanceDictionary(new COSDictionary());
            appearance.setNormalAppearance(appearanceStream);

            link.setRectangle(rectangle);
            // close and save
            if (pAdESSignatureParameters.getLink() != null) {
                annotations.add(link);
            }
            appearanceStream.getCOSObject().setNeedToBeUpdated(true);
            appearance.getCOSObject().setNeedToBeUpdated(true);
            rectangle.getCOSArray().setNeedToBeUpdated(true);
            link.getCOSObject().setNeedToBeUpdated(true);
            form.getCOSObject().setNeedToBeUpdated(true);
            COSArrayList<PDAnnotation> list = (COSArrayList<PDAnnotation>) annotations;
            COSArrayList.converterToCOSArray(list).setNeedToBeUpdated(true);
            document.getPages().getCOSObject().setNeedToBeUpdated(true);
            page.getCOSObject().setNeedToBeUpdated(true);
            document.getDocumentCatalog().getCOSObject().setNeedToBeUpdated(true);
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
        if (token == null || parameters.isExternalPkcs7Signature()) {
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

        List<PDSignature> pdSignatures = doc.getSignatureDictionaries();
        if (parameters.getCertifiedLevel() != null && (pdSignatures == null || pdSignatures.isEmpty())) {
            addCertificationLevel(parameters, doc, signature);
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
            doc = Loader.loadPDF(originalBytes, password);

            List<PDSignature> pdSignatures = doc.getSignatureDictionaries();
            if (Utils.isCollectionNotEmpty(pdSignatures)) {
                logger.debug("{} signature(s) found", pdSignatures.size());

                PdfDict catalog = new PdfBoxDict(doc.getDocumentCatalog().getCOSObject(), doc);
                PdfDssDict dssDictionary = PdfDssDict.extract(catalog);

                for (PDSignature signature : pdSignatures) {
                    String subFilter = signature.getSubFilter();

                    try{
                        byte[] cms = null;
                        try{
                            cms = signature.getContents(originalBytes);
                            if (Utils.isStringEmpty(subFilter) || Utils.isArrayEmpty(cms)) {
                                logger.warn("Wrong signature with empty subfilter or cms.");
                                continue;
                            }
                        }catch (Exception e){
                            logger.warn(e.getMessage(), e);
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
                    }catch (Exception e){
                        logger.warn(e.getMessage(), e);
                    }
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
            doc = Loader.loadPDF(originalBytes, password);
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
            pdDocument = Loader.loadPDF(new RandomAccessReadBuffer(inputStream), parameters.getPassword());
            if (Utils.isCollectionNotEmpty(callbacks)) {
                final COSDictionary cosDictionary = pdDocument.getDocumentCatalog().getCOSObject();
                COSDictionary dss = (COSDictionary) cosDictionary.getDictionaryObject("DSS");
                cosDictionary.setItem("DSS", buildDSSDictionary(dss, callbacks));
                cosDictionary.setNeedToBeUpdated(true);
            }

            if (pdDocument.getDocumentId() == null) {
                final byte[] documentIdBytes = DSSUtils.digest(DigestAlgorithm.MD5, parameters.bLevel().getSigningDate().toString().getBytes());
                pdDocument.setDocumentId(DSSUtils.toLong(documentIdBytes));
            }
            pdDocument.saveIncremental(outputStream);

        } catch (Exception e) {
            throw new DSSException(e);
        } finally {
            Utils.closeQuietly(pdDocument);
        }
    }

    private COSDictionary buildDSSDictionary(COSDictionary current, List<DSSDictionaryCallback> callbacks) throws Exception {

        COSDictionary dss = new COSDictionary();

        Map<String, COSStream> streams = new HashMap<>();

        Set<CRLToken> allCrls = new HashSet<>();
        Set<OCSPToken> allOcsps = new HashSet<>();
        Set<CertificateToken> allCertificates = new HashSet<>();

        COSDictionary vriDictionary;
        if (current != null) {
            vriDictionary = (COSDictionary) current.getDictionaryObject("VRI");
            if (vriDictionary == null) {
                vriDictionary = new COSDictionary();
            }
        } else {
            vriDictionary = new COSDictionary();
        }

        for (DSSDictionaryCallback callback : callbacks) {

            // We can't use CMSSignedData, the pdSignature content is trimmed
            // (000000)
            PdfSignatureInfo pdfSignatureInfo = callback.getSignature().getPdfSignatureInfo();
            final byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, pdfSignatureInfo.getContent());
            String hexHash = Utils.toHex(digest).toUpperCase();

            COSDictionary sigVriDictionary = (COSDictionary) vriDictionary.getDictionaryObject(hexHash);
            if (sigVriDictionary == null) {
                sigVriDictionary = new COSDictionary();
            }
            sigVriDictionary.setDirect(true);

            if (Utils.isCollectionNotEmpty(callback.getCertificates())) {
                COSArray vriCertArray = (COSArray) sigVriDictionary.getDictionaryObject("Cert");
                if (vriCertArray == null) {
                    vriCertArray = new COSArray();
                }
                for (CertificateToken token : callback.getCertificates()) {
                    vriCertArray.add(getStream(streams, token));
                    allCertificates.add(token);
                }
                sigVriDictionary.setItem("Cert", vriCertArray);
            }

            if (Utils.isCollectionNotEmpty(callback.getOcsps())) {
                COSArray vriOcspArray = (COSArray) sigVriDictionary.getDictionaryObject("OCSP");
                if (vriOcspArray == null) {
                    vriOcspArray = new COSArray();
                }
                for (OCSPToken token : callback.getOcsps()) {
                    vriOcspArray.add(getStream(streams, token));
                    allOcsps.add(token);
                }
                sigVriDictionary.setItem("OCSP", vriOcspArray);
            }

            if (Utils.isCollectionNotEmpty(callback.getCrls())) {
                COSArray vriCrlArray = (COSArray) sigVriDictionary.getDictionaryObject("CRL");
                if (vriCrlArray == null) {
                    vriCrlArray = new COSArray();
                }
                for (CRLToken token : callback.getCrls()) {
                    vriCrlArray.add(getStream(streams, token));
                    allCrls.add(token);
                }
                sigVriDictionary.setItem("CRL", vriCrlArray);
            }

            vriDictionary.setItem(hexHash, sigVriDictionary);
        }
        dss.setItem("VRI", vriDictionary);


        COSArray arrayAllCerts;
        if (current != null) {
            arrayAllCerts = (COSArray) current.getDictionaryObject("Certs");
            if (arrayAllCerts == null) {
                arrayAllCerts = new COSArray();
            }
        } else {
            arrayAllCerts = new COSArray();
        }
        if (Utils.isCollectionNotEmpty(allCertificates)) {
            for (CertificateToken token : allCertificates) {
                arrayAllCerts.add(getStream(streams, token));
            }
        }
        dss.setItem("Certs", arrayAllCerts);

        COSArray arrayAllOcsps;
        if (current != null) {
            arrayAllOcsps = (COSArray) current.getDictionaryObject("OCSPs");
            if (arrayAllOcsps == null) {
                arrayAllOcsps = new COSArray();
            }
        } else {
            arrayAllOcsps = new COSArray();
        }
        if (Utils.isCollectionNotEmpty(allOcsps)) {
            for (OCSPToken token : allOcsps) {
                arrayAllOcsps.add(getStream(streams, token));
            }
        }
        dss.setItem("OCSPs", arrayAllOcsps);

        COSArray arrayAllCrls;
        if (current != null) {
            arrayAllCrls = (COSArray) current.getDictionaryObject("CRLs");
            if (arrayAllCrls == null) {
                arrayAllCrls = new COSArray();
            }
        } else {
            arrayAllCrls = new COSArray();
        }
        if (Utils.isCollectionNotEmpty(allCrls)) {
            for (CRLToken token : allCrls) {
                arrayAllCrls.add(getStream(streams, token));
            }
        }
        dss.setItem("CRLs", arrayAllCrls);

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