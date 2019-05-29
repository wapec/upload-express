import * as express from 'express';
import * as multer from 'multer';
import * as cors from 'cors';
import * as fs from 'fs';
import * as path from 'path';
import * as Loki from 'lokijs';
import {cleanFolder, fileFilter, loadCollection} from './utils';

// setup
const DB_NAME = 'db.json';
const COLLECTION_NAME = 'images';
const UPLOAD_PATH = 'uploads';
const upload = multer({dest: `${UPLOAD_PATH}/`, fileFilter: fileFilter});
const db = new Loki(`${UPLOAD_PATH}/${DB_NAME}`, {persistenceMethod: 'fs'});

// optional: clean all data before start
cleanFolder(UPLOAD_PATH);

// app
const app = express();
app.use(cors());

app.listen(3000, function () {
  console.log('listening on port 3000!');
});

app.post('/store', upload.single('file'), async (req, res) => {
  try {
    const col = await loadCollection(COLLECTION_NAME, db);
    const data = col.insert(req.file);


    db.saveDatabase();
    res.send({id: data.$loki, fileName: data.filename, originalName: data.originalname});
  } catch (err) {
    res.sendStatus(400);
  }
});

app.post('/files/upload', upload.array('files', 12), async (req, res) => {
  try {
    const col = await loadCollection(COLLECTION_NAME, db);
    let data = [].concat(col.insert(req.files));

    db.saveDatabase();
    res.send(data.map(x => ({id: x.$loki, fileName: x.filename, originalName: x.originalname})));
  } catch (err) {
    res.sendStatus(400);
  }
});

app.get('/files', async (req, res) => {
  try {
    const col = await loadCollection(COLLECTION_NAME, db);
    res.send(col.data);
  } catch (err) {
    res.sendStatus(400);
  }
});

app.get('/files/:id', async (req, res) => {
  try {
    const col = await loadCollection(COLLECTION_NAME, db);
    const result = col.get(req.params.id);

    if (!result) {
      res.sendStatus(404);
      return;
    }

    res.setHeader('Content-Type', result.mimetype);
    fs.createReadStream(path.join(UPLOAD_PATH, result.filename)).pipe(res);
  } catch (err) {
    res.sendStatus(400);
  }
});
