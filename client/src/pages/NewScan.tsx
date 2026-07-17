import { useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { scanByPath, uploadAndScan } from '../api/client';
import LoadingSpinner from '../components/LoadingSpinner';
import { useTranslation } from '../i18n';
import { IconPackage, IconUpload } from '../components/Icons';

export default function NewScan() {
  const { t } = useTranslation();
  const [pathInput, setPathInput] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState('');
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  const handlePathScan = async () => {
    if (!pathInput.trim()) return;
    setScanning(true);
    setError('');
    try {
      const result = await scanByPath(pathInput.trim());
      navigate(`/scan/${result.id}`);
    } catch (err: any) {
      setError(err.response?.data?.error || t.newScan.scanFailed);
      setScanning(false);
    }
  };

  const handleFileScan = async () => {
    if (!file) return;
    setScanning(true);
    setError('');
    try {
      const result = await uploadAndScan(file);
      navigate(`/scan/${result.id}`);
    } catch (err: any) {
      setError(err.response?.data?.error || t.newScan.uploadFailed);
      setScanning(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files[0];
    if (f?.name.endsWith('.zip')) setFile(f);
  };

  if (scanning) return <LoadingSpinner text={t.newScan.scanning} />;

  return (
    <div>
      <h1 className="text-3xl font-bold text-white mb-2">{t.newScan.title}</h1>
      <p className="text-dark-500 mb-8">{t.newScan.subtitle}</p>

      {error && <div className="bg-red-500/10 border border-red-500/30 text-red-400 px-4 py-3 rounded-lg mb-6">{error}</div>}

      <div className="grid grid-cols-2 gap-8">
        {/* Upload ZIP */}
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-6">
          <h2 className="text-lg font-semibold text-white mb-4">{t.newScan.uploadZip}</h2>
          <div
            className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-colors ${dragOver ? 'border-blue-500 bg-blue-500/10' : 'border-dark-600 hover:border-dark-500'}`}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            onClick={() => fileRef.current?.click()}
          >
            <input ref={fileRef} type="file" accept=".zip" className="hidden" onChange={(e) => setFile(e.target.files?.[0] || null)} />
            {file ? (
              <div>
                <div className="mb-2 flex justify-center text-blue-400"><IconPackage size={40} /></div>
                <div className="text-white font-medium">{file.name}</div>
                <div className="text-dark-500 text-sm mt-1">{(file.size / 1024).toFixed(1)} KB</div>
              </div>
            ) : (
              <div>
                <div className="mb-2 flex justify-center text-dark-500"><IconUpload size={40} /></div>
                <div className="text-gray-400">{t.newScan.dropzone}</div>
                <div className="text-dark-500 text-sm mt-1">{t.newScan.maxSize}</div>
              </div>
            )}
          </div>
          <button
            onClick={handleFileScan}
            disabled={!file}
            className="w-full mt-4 bg-blue-600 hover:bg-blue-500 disabled:bg-dark-700 disabled:text-dark-500 text-white py-3 rounded-lg font-medium transition-colors"
          >
            {t.newScan.uploadAndScan}
          </button>
        </div>

        {/* Path Input */}
        <div className="bg-dark-800 border border-dark-700 rounded-xl p-6">
          <h2 className="text-lg font-semibold text-white mb-4">{t.newScan.directoryPath}</h2>
          <div className="space-y-4">
            <div>
              <label className="text-sm text-dark-500 mb-2 block">{t.newScan.pathLabel}</label>
              <input
                type="text"
                value={pathInput}
                onChange={(e) => setPathInput(e.target.value)}
                placeholder={t.newScan.pathPlaceholder}
                className="w-full bg-dark-900 border border-dark-700 rounded-lg px-4 py-3 text-white placeholder:text-dark-600 focus:border-blue-500 focus:outline-none transition-colors font-mono text-sm"
                onKeyDown={(e) => e.key === 'Enter' && handlePathScan()}
              />
            </div>
            <button
              onClick={handlePathScan}
              disabled={!pathInput.trim()}
              className="w-full bg-blue-600 hover:bg-blue-500 disabled:bg-dark-700 disabled:text-dark-500 text-white py-3 rounded-lg font-medium transition-colors"
            >
              {t.newScan.scanDirectory}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
