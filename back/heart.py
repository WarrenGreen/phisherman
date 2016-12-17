import numpy as np
import cv2
import _mysql
from shutil import copyfile

class heart:
    MYSQL_USER = ""
    MYSQL_PASS = ""
    MYSQL_DB = ""
    
    SELECT_PAGE_FILENAMES_DOMAIN = """SELECT fileName, domainId from pages"""
    SELECT_DOMAINS_FOR_ID = """SELECT domain from domains where domainId="""
    SELECT_SAFE_DOMAINS = """SELECT url from safe"""
    INSERT_SAFE = """INSERT INTO mislabled (clientId, url) VALUES ('{0}', '{1}')"""
    INSERT_REPORT_MALICIOUS = """INSERT INTO reported (url) VALUES ('{0}')"""
    INSERT_DETECTION = """INSERT INTO detected (url, domain, filename, matched) VALUES ('{0}', '{1}', '{2}', '{3}')"""   

    DIRECTORY = "tmp/"
    TRAINING_DATA_DIR = "trainingData/"
    SAVE_DIR = "save/"

    MIN_MATCH_COUNT = 100
    MIN_MATCH_RATIO = 0.15

    INFO = True

    def __init__(self):
        # Initiate SIFT detector
        self.sift = cv2.SIFT()
    
        #build index
        filesDes = []
        self.files = self.getImageFilesInfo()
        for fileObj in self.files:
            filename = fileObj["filename"]
            trainImg = cv2.imread(heart.TRAINING_DATA_DIR+filename,0)
            trainKP, trainDes = self.sift.detectAndCompute(trainImg, None)
            filesDes.append(trainDes)
        FLANN_INDEX_KDTREE = 0
        index_params = dict(algorithm = FLANN_INDEX_KDTREE, trees = 5)
        search_params = dict(checks = 50)
        
        self.flann = cv2.FlannBasedMatcher(index_params, search_params)
        self.flann.add(filesDes)
        self.flann.train()
        self.safe = []
        self.getSafe()
        self.malicious = []
    
    ##
    # Returns open mysql connection based on global params
    ##
    def getDb(self):
        db =_mysql.connect(host="localhost",user=heart.MYSQL_USER, passwd=heart.MYSQL_PASS, db=heart.MYSQL_DB)
        return db
    
    ##
    # Retrieves known sites image metadata
    ##
    def getImageFilesInfo(self):
        db = self.getDb()
        db.query(heart.SELECT_PAGE_FILENAMES_DOMAIN)
        r = db.store_result()
        files = []
    
        row = r.fetch_row()
        while len(row) > 0:
            fileObj = {}
            domains = []
            pageFile, domainId = row[0]
            db.query(heart.SELECT_DOMAINS_FOR_ID + str(domainId))
            rr = db.store_result()
            drow = rr.fetch_row()
            while(len(drow) > 0):
                domains.append(drow[0][0])
                drow = rr.fetch_row()
    
            files.append({"index":len(files), "filename":pageFile, "domains":domains})
            row = r.fetch_row()
    
        db.close()
    
        return files

    def markSafe(self, clientId, url):
        db = self.getDb()
        db.query(heart.INSERT_SAFE.format(clientId, url))
        db.close()

    def reportMalicious(self, url):
        db = self.getDb()
        db.query(heart.INSERT_REPORT_MALICIOUS.format(url))
        db.close()

    ##
    # Retrive known safe urls cache
    ##
    def getSafe(self):
        db = self.getDb()
        db.query(heart.SELECT_SAFE_DOMAINS)
        r = db.store_result()
        row = r.fetch_row()
        while(len(row) > 0):
            self.safe.append(row[0][0])
            row = r.fetch_row()
        db.close()

    ##
    # Record detection hit
    ##
    def recordDetection(self, url, domain, filename, matchFile):
        db = self.getDb()
        insertQuery = heart.INSERT_DETECTION.format(url, domain, filename, matchFile)
        db.query(insertQuery)
        db.close()
    
    def getDescriptors(self, filename, domain, url):
        img = cv2.imread(heart.DIRECTORY+filename,0)    
        # SIFT keypoints and descriptors
        kp, des = self.sift.detectAndCompute(img, None)
        
        matches = self.flann.knnMatch(des, k=2)
        
        # store all the good matches per Lowe's ratio test.
        good = []
        for m,n in matches:
            if m.distance < 0.7*n.distance:
                good.append(m)
        
        matchRatio = (1.0*len(good))/(1.0*len(matches)+1)

        if(INFO):
            print "matches: " + str(len(matches))
            print "good: " + str(len(good))
            print "self.MIN_MATCH_COUNT: " + str(len(matches)*0.15)
            print "filename: " + filename

        if self.MIN_MATCH_RATIO <= matchRatio and len(good) > self.MIN_MATCH_COUNT:
            if( domain not in self.files[good[0].imgIdx]["domains"]):
                if(INFO):
                    print "index: " + str(good[0].imgIdx) + " == " + str(self.files[good[0].imgIdx]["index"])
                    print domain + " not in "
		            print self.files[good[0].imgIdx]["domains"]
                copyfile(heart.DIRECTORY+filename, heart.SAVE_DIR+filename)
                self.recordDetection(url, domain, filename, self.files[good[0].imgIdx]["filename"])
                return filename
            else:
                return False
        
        else:
            print "Not enough matches are found - %d/%d" % (len(good),heart.MIN_MATCH_COUNT)
            return False
