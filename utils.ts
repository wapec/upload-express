import * as del from 'del';
import * as Loki from 'lokijs';

const loadCollection = function (colName, db: Loki): Promise<Loki.Collection<any>> {
  return new Promise(resolve => {
    db.loadDatabase({}, () => {
      const _collection = db.getCollection(colName) || db.addCollection(colName);
      resolve(_collection);
    })
  });
};

const fileFilter = function (req, file, cb) {
  // accept image only
  if (!file.originalname.match(/^(.*\.(?!(htm|html|class|js|dll|bat|sfx|tmp|cmd|lnk|inf"scf)$))?[^.]*$/i)) {
    return cb(new Error('malicious file type!'), false);
  }
  cb(null, true);
};

const cleanFolder = function (folderPath) {
  // delete files inside folder but not the folder itself
  del.sync([`${folderPath}/**`, `!${folderPath}`]);
};

export { cleanFolder, fileFilter, loadCollection }
