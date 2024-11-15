from flask import Flask, request, Blueprint, jsonify
import numpy as np
import cv2 as cv
import re
import os
import pytesseract
from pytesseract import Output
from fuzzywuzzy import fuzz
from math import ceil
import platform

ocr = Blueprint('ocr', __name__)

# if platform.system() == 'Windows':
#     pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
# elif platform.system() == 'Darwin':  # macOS
#     pytesseract.pytesseract.tesseract_cmd = '/usr/local/bin/tesseract'
# else:  # Linux
#     pytesseract.pytesseract.tesseract_cmd = '/usr/bin/tesseract'

pytesseract.pytesseract.tesseract_cmd = '/usr/bin/tesseract'


# img = cv.imread('images/image25.jpg')
# aspect_ratio = img.shape[1] / img.shape[0]

# Constants
WIDTH_IMG = 605
HEIGHT_IMG = 806
LINE_PADDING = 5
ACCEPTED_TEXT_PROBABILITY = 0.3
RECEIPT_AREA = 20000
CROP_MARGIN_PERCENTAGE = 0.03  # 3% crop from all sides
PERCENTAGE_OF_RECEIPT_IN_FRAME = 0.6

DATE_PATTERN = r'(\d{1,2}[-/.\s]\d{1,2}[-/.\s]\d{2,4})'
DECIMAL_NUMBER_PATTERN = r'^\d*\.\d+$'
POSTAL_CODE_FIRST_HALF_PATTERN = r'^[A-Z]{1,2}[0-9][0-9]?[A-Z]?$'
POSTAL_CODE_SECOND_HALF_PATTERN = r'^[0-9][A-Z]{2}$' 
POSTAL_CODE_PATTERN = r'([A-Z]{1,2}[0-9][A-Z0-9]?\s?[0-9][A-Z]{2})'
# QUANTITY_PATTERN = r'^\b([1-9][0-9]{0,2})x?\b$'
QUANTITY_PATTERN = r'^(?:[lIi|1-9][0-9]{0,2})x?$'
PRICE_PATTERN = r'^[~-]?[c£$€]?[~-]?(\d{1,3}(?:,\d{3})*[.,:]\d{2})$'
PERCENTAGE_PATTERN = r'([1-9][0-9]?|100)%'
CC_PATTERN = r'\bC[ce]\b' 
THOUSAND_DOLLAR_PATTERN = r"^[-~]?[£$€]?[-~]?\d{1,3}(,\d{3})*(\.\d+)?$"
DECIMAL_DOLLAR_PATTERN = r"^[-~]?[£$€]?[-~]?\d+,\d{2}$"
LINE_TERMINATOR_PATTERN = re.compile(r"\b(?:TOTAL|VAT|AT|AMOUNT|CARD|DISCOUNT|SUBTOTAL|SUBLOLAL)\b", re.IGNORECASE)


UNWANTED_STRINGS = set(["=——", "=—", "»", "©"])
SHOP_NAMES = set()
CURRENCY_SYMBOLS = set(['$', '€', '£', '¥', '₹', 'RM', 'c'])
KEYWORD_ADDRESS = set()
LINE_TERMINATOR_KEYWORDS = set(["TOTAL", "Total", "VAT", "AT", "AMOUNT", "Amount", "CARD", "Card", "DISCOUNT"
                                , "Discount", "SUBTOTAL", "Subtotal", "Sublolal", "subtotal"])

current_dir = os.path.dirname(os.path.abspath(__file__))

unwantedStringsFilePath = os.path.join(current_dir, "../dataSets/unwanted_strings.txt")
shopNamesFilePath = os.path.join(current_dir, "../dataSets/shop_names.txt")
# currencySymbolsFilePath = "dataSets/currency_symbols.txt"
keywordAdressesFilePath = os.path.join(current_dir, "../dataSets/keyword_addresses.txt")

def getDataFromFiles(filePath, set):
    with open(filePath, 'r') as file:
        for line in file:
            # Strip any leading/trailing whitespace and add to the set
            set.add(line.strip())

getDataFromFiles(unwantedStringsFilePath, UNWANTED_STRINGS)
getDataFromFiles(shopNamesFilePath, SHOP_NAMES)
getDataFromFiles(keywordAdressesFilePath, KEYWORD_ADDRESS)

def preProcessReceipt(img):
    grayscale = cv.cvtColor(img, cv.COLOR_BGR2GRAY)
    h = 20
    denoisedImg = cv.fastNlMeansDenoising(grayscale, h=h)
    blockSize = 15
    C = 2
    imgBlackAndWhite = cv.adaptiveThreshold(denoisedImg, 255, cv.ADAPTIVE_THRESH_GAUSSIAN_C, cv.THRESH_BINARY, blockSize, C)
    invertedImg = cv.bitwise_not(imgBlackAndWhite)
    imgErode = cv.erode(invertedImg, (5, 5), iterations=0)
    imgResult = cv.dilate(imgErode, (5, 5), iterations=0)
    return imgResult

def extractReceipt(img):
    gray = cv.cvtColor(img, cv.COLOR_BGR2GRAY)
    blurred = cv.GaussianBlur(gray, (5, 5), 2)
    rectKernel = cv.getStructuringElement(cv.MORPH_RECT, (5, 5))
    dilate = cv.dilate(blurred, rectKernel, iterations=2)
    edged = cv.Canny(dilate, 20, 80, apertureSize=3)
    threshold = np.mean(edged)
    thresh, binary = cv.threshold(edged, threshold, 255, cv.THRESH_BINARY)
    rectKernel = cv.getStructuringElement(cv.MORPH_RECT, (5, 5))
    dilated = cv.dilate(binary, rectKernel, iterations=1)
    
    # Find contours
    contours, _ = cv.findContours(dilated, cv.RETR_EXTERNAL, cv.CHAIN_APPROX_SIMPLE)
    
    # Filter contours based on area and find the largest one
    largest_contour = max(contours, key=cv.contourArea)
    
    # Get the minimum-area rectangle for the largest contour
    x, y, w, h = cv.boundingRect(largest_contour)
    areaOfLargestContour = w * h
    areaOfFrame = WIDTH_IMG*HEIGHT_IMG
    # print("area of bounding box: ", areaOfLargestContour)
    # print("area of frame:", WIDTH_IMG*HEIGHT_IMG)
    # Extract the ROI (Region of Interest) using the bounding box
    receipt_roi = img[y:y+h, x:x+w]
    
    if areaOfLargestContour/areaOfFrame >= PERCENTAGE_OF_RECEIPT_IN_FRAME:
        # Extract the ROI (Region of Interest) using the bounding box
        receipt_roi = img[y:y+h, x:x+w]
        # Optionally draw a rectangle around the receipt in the original image
        # cv.rectangle(img, (x, y), (x + w, y + h), (0, 255, 0), 2)

        resizedROI = cv.resize(receipt_roi, (int(w*1.2), int(h*1.2)), interpolation=cv.INTER_AREA)
        return resizedROI
    #     cv.imshow("Extracted Receipt", receipt_roi)
    #     cv.imshow("Resized ROI", resizedROI)

    # # Display the original image with the frame
    # cv.imshow("dilated", dilated)
    # cv.imshow("Image with Receipt Frame", img)

    # # Wait for a key press and close the windows
    # cv.waitKey(0)
    # cv.destroyAllWindows()

    return None

def cleanCommaNumber(num_string):
    # Check and replace based on matched pattern
    if re.match(THOUSAND_DOLLAR_PATTERN, num_string):
        return num_string.replace(",", "")  # Remove commas for thousands format
    elif re.match(DECIMAL_DOLLAR_PATTERN, num_string):
        return num_string.replace(",", ".")  # Convert comma to dot for decimal
    return num_string  # Return unchanged if no match


def getOCRDetails(image, custom_config, y_threshold=10, conf_threshold=ACCEPTED_TEXT_PROBABILITY):
    w = image.shape[1]
    h = image.shape[0]
    w1 = int(w * 0.015)
    w2 = int(w * 0.985)
    h2 = int(h * 0.99)
    img = image[:h2, w1:w2]
    ocr_data = pytesseract.image_to_data(img, config=custom_config, output_type=Output.DICT)

    lines = []
    line_words = []
    last_y = -1
    # details = [storeName, date, address, potal code]
    details = [None, None, set(), None]
    
    # foodItems = {(quantity, food name) : total price}
    global foodItems

    for i in range(len(ocr_data['text'])):
        word = ocr_data['text'][i].strip()
        conf = int(ocr_data['conf'][i])
    
        dateMatch = re.match(DATE_PATTERN, word)
        fullPostalCodeMatch = re.match(POSTAL_CODE_PATTERN, word)
        frontPostalCodeMatch = re.match(POSTAL_CODE_FIRST_HALF_PATTERN, word)

        if word in SHOP_NAMES: details[0] = word
        if dateMatch: details[1] = dateMatch.group()

        if fullPostalCodeMatch: details[3] = fullPostalCodeMatch.group()
        if frontPostalCodeMatch and i+1 < len(ocr_data['text']):
            backPostalCodeMatch = re.match(POSTAL_CODE_SECOND_HALF_PATTERN, ocr_data['text'][i+1].strip())
            if backPostalCodeMatch: details[3] = frontPostalCodeMatch.group() + " " + backPostalCodeMatch.group()

        
        if not word or conf < conf_threshold or word in UNWANTED_STRINGS:
            continue

        y = ocr_data['top'][i]  # Y-coordinate of the word
        if last_y == -1 or abs(last_y - y) < y_threshold:  # Same line
            line_words.append(word)
        else:  # New line detected
            if line_words:
                lines.append(line_words)
            line_words = [word]

        last_y = y

    if line_words:
        lines.append(line_words)
    

    foundAddress = False
    
    # foodItems = [[quantity, item, price of 1 item]]
    foodItems = [] 


    for line in lines:
        for word in line:
            if word in KEYWORD_ADDRESS and not foundAddress: # we know the whole line is potentially an address
                for i in range(len(line)-1, 0, -1):
                    if line[i][0] in CURRENCY_SYMBOLS or re.match(DECIMAL_NUMBER_PATTERN, line[i]): # we know its a food line, not an address
                        foundAddress = True
                        break
                
                if not foundAddress:
                    details[2].add(" ".join(line))

        if len(line[-1]) == 1: line.pop() # remove A from Lidl receipts

        if len(line) >= 2: # at least food item and price exist
            #  or re.match(PRICE_PATTERN, line[-2])
            if re.match(PRICE_PATTERN, line[-1]): # food item line, also total price
                if line[0] in LINE_TERMINATOR_KEYWORDS: break
                if LINE_TERMINATOR_PATTERN.search(" ".join(line)): break

                # detected some anomaly on last index, but 2nd last index is a price
                # if re.match(PRICE_PATTERN, line[-1]) == None and re.match(PRICE_PATTERN, line[-2]):
                    # line = line[:-1]

                # if line[-1] == "1.79": print("sssssss")

                line[-1] = line[-1].replace(":", ".").replace("~", "-")
                line[-1] = cleanCommaNumber(line[-1])
                # if line[-1] == "1.04": print(line[-2])
                total = 0

                if line[-1][0] == "-" and line[-1][1] in CURRENCY_SYMBOLS:
                    total = -1 * float(line[-1][2:])
                elif line[-1][0] in CURRENCY_SYMBOLS:
                    total = float(line[-1][1:])
                else:
                    total = float(line[-1])


                if re.match(PRICE_PATTERN, line[-2]): # price of 1 item
                    # if line[-2] == "£2.79": 
                    #     print(line[-2], total)

                    line[-2] = cleanCommaNumber(line[-2])
                    # if line[-1] == "1.79": print('osas')
                    priceOneItem = 0
                    if line[-2][0] in CURRENCY_SYMBOLS:
                        priceOneItem = float(line[-2][1:])
                    else:
                        priceOneItem = float(line[-2])

                    foodItems.append([ceil(abs(total/priceOneItem)), " ".join(line[:-2]), priceOneItem])

                elif re.match(QUANTITY_PATTERN, line[0]):
                    quantity = line[0]

                    # print(quantity)
                    quantity = re.sub(r'[lIi|]', '1', quantity, count=1)
                    # print(quantity)
                    # print("quantity", type(quantity))
                    if quantity[-1] == "x": quantity = quantity[0:-1]
                    foodItems.append([int(quantity), " ".join(line[1:-1]), total/int(quantity)])
                
                else: # just assume one item
                    if re.match(DATE_PATTERN, line[0]) or re.match(DATE_PATTERN, line[1]): continue
                    foodItems.append([1, " ".join(line[:-1]), total])
            
            # if price is not detected but percentage detected
            # it is a discount
            elif re.match(PERCENTAGE_PATTERN, line[0]):
                foodItems.append([1, " ".join(line), 0])

    return lines, details, foodItems

def getProcessedFoodDetails(foodDetails):
    result= []
    if foodDetails: result.append(foodDetails[0])
    foundDiscount = False

    for i in range(1,len(foodDetails)):
        curQuantity = foodDetails[i][0]
        curItem = foodDetails[i][1]
        curPrice = foodDetails[i][2]

        prevQuantity = foodDetails[i-1][0]
        prevItem = foodDetails[i-1][1]
        prevPrice = foodDetails[i-1][2]

        if curPrice < 0: # discount or free, so update previous element
            if curPrice/prevQuantity > foodDetails[i-1][2]:
                match = re.search(PERCENTAGE_PATTERN, curItem)
                discount = 0

                if match: discount = 1 - (int(match.group(1)) / 100)

                if discount != 0 and not foundDiscount:
                    result[-1][2] = round(prevPrice * discount, 2)
                    foundDiscount = True
                
            else:
                # print(result[-1][2], curPrice/foodDetails[i-1][0])
                result[-1][2] += (curPrice/prevQuantity)
                foundDiscount = True
        
        else: # could still have discount if OCR did not detect negative
            matchPercentage = re.search(PERCENTAGE_PATTERN, curItem)
            matchCc = re.search(CC_PATTERN, curItem)

            discount = 0
            
            if matchPercentage: discount = 1 - (int(matchPercentage.group(1)) / 100)

            if matchCc: 
                result[-1][2] = curPrice
                foundDiscount = True

            elif discount != 0 and not foundDiscount:
                result[-1][2] = round(prevPrice * discount, 2)
                foundDiscount = True
            
            else:
                # found discount but previous element already discounted
                if (re.search(PERCENTAGE_PATTERN, curItem) or re.search(CC_PATTERN, curItem)) and foundDiscount:
                     foundDiscount = False
                     continue

                result.append(foodDetails[i])
                foundDiscount = False

    return result


def merge_items(result_original, result_canny, threshold=60):
    merged_items = []

    # Store the original items in a separate list for checking
    # original_items = [item[1] for item in result_original]

    for item_canny in result_canny:
        # Check if the current item from result_canny matches any item in result_original
        matched = False
        for item_original in result_original:
            similarity = fuzz.ratio(item_canny[1], item_original[1])
            if similarity >= threshold:
                # If a match is found, update the quantity and price
                #print(item_original[0])

                # if item_canny[0] < item_original[0]:
                #     item_original[2] = item_original[2] * item_original[0]
                #     item_original[0] = item_canny[0]
                # elif item_canny[0] > item_original[0]:
                #     item_canny[2] = item_canny[2] * item_canny[0]
                #     item_canny[0] = item_original[0]

                merged_items.append([max(int(item_canny[0]), int(item_original[0])), item_canny[1], 
                                     min(float(item_canny[2]), float(item_original[2]))])
                matched = True
                break  # Stop checking further if a match is found

        # If no match was found, add the item to merged_items if its not a percentage pattern
        if not matched and re.match(PERCENTAGE_PATTERN, item_canny[1]) == None:
            merged_items.append(item_canny)

    # Now add items from result_original that are not in merged_items
    #print(merged_items)
    #print(result_original)
    # print(result_canny)
    for item_original in result_original:
        # Check if the item is already in merged_items
        if all(fuzz.ratio(item_original[1], merged_item[1]) < threshold for merged_item in merged_items):
            merged_items.append(item_original)

    return merged_items

def displayImagesSideBySide(imgOriginal, imgCanny):
    img1_resized = cv.resize(imgOriginal, (WIDTH_IMG, HEIGHT_IMG))
    img2_resized = cv.resize(imgCanny, (WIDTH_IMG, HEIGHT_IMG))

    img2_resized = np.stack([img2_resized] * 3, axis=-1)

    combined_img = np.hstack((img1_resized, img2_resized))

    cv.imshow("Original and Black-and-White Image", combined_img)
    cv.waitKey(0)
    cv.destroyAllWindows()

def processReceipt(img):
    img = cv.resize(img, (WIDTH_IMG, HEIGHT_IMG), interpolation=cv.INTER_AREA)
    imgContour = img.copy()

    receipt = extractReceipt(img)
    if receipt is None: receipt = img

    # cv.imshow("Processed Frame", receipt)
    
    imgReceiptCanny = preProcessReceipt(receipt)

    custom_config = r'--oem 3 --psm 6'

    pytesseract_data_canny, detailsCanny, foodDetailsCanny = getOCRDetails(imgReceiptCanny, custom_config, conf_threshold=ACCEPTED_TEXT_PROBABILITY, y_threshold=10)
    pytesseract_data_original, detailsOriginal, foodDetailsOriginal = getOCRDetails(receipt, custom_config, conf_threshold=ACCEPTED_TEXT_PROBABILITY, y_threshold=13)

    # print("Canny results:")
    # print(pytesseract_data_canny)
    # print("Original Results:")
    # print(pytesseract_data_original)

    print("Canny details:")
    print(detailsCanny)
    print("Original details:")
    print(detailsOriginal)

    # print("Canny food details")
    # print(foodDetailsCanny)
    # print("Original food details")
    # print(foodDetailsOriginal)

    for i in range(len(detailsOriginal)):
        # for second last element check if empty set
        if i == len(detailsOriginal) - 2:            
            if detailsOriginal[i] == set():                
                detailsOriginal[i] = detailsCanny[i]            
        elif detailsOriginal[i] is None:
            detailsOriginal[i] = detailsCanny[i]

    
    resultCanny = getProcessedFoodDetails(foodDetailsCanny)
    resultOriginal = getProcessedFoodDetails(foodDetailsOriginal)

    # print("result Canny")
    # print(resultCanny)
    # print("result Original")
    # print(resultOriginal)


    result = merge_items(resultCanny, resultOriginal)

    print("Final Result")
    print(result)
    return (detailsOriginal, result)

    # displayImagesSideBySide(deskewedReceipt, imgReceiptCanny)
    # cv.imshow("Contour image", imgContour)
    # cv.waitKey(0)



@ocr.route('/get-ocr', methods=['GET'])
def get_ocr():
    user_id = request.args.get('userId')
    # Logic for OCR
    # Placeholder response for now
    return jsonify({'ocr': 'Text extracted from image'}), 200