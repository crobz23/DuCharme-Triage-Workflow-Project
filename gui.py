import { useState } from 'react';
import { Button } from './components/ui/button';
import { Label } from './components/ui/label';
import { Input } from './components/ui/input';
import { ScrollArea } from './components/ui/scroll-area';
import { FileText, Upload, Trash2, X } from 'lucide-react';

export default function App() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [filePath, setFilePath] = useState<string>('');
  const [results, setResults] = useState<string>('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      setFilePath(file.name);
    }
  };

  const handleBrowseClick = () => {
    document.getElementById('fileInput')?.click();
  };

  const handleAnalyze = async () => {
    if (!selectedFile) {
      setResults('Please select a log file first.');
      return;
    }

    setIsAnalyzing(true);
    setResults('Analyzing log file...\n');

    // Simulate analysis process
    setTimeout(() => {
      const mockResults = `Analysis Results for: ${selectedFile.name}
=====================================

File Information:
- File Name: ${selectedFile.name}
- File Size: ${(selectedFile.size / 1024).toFixed(2)} KB
- File Type: ${selectedFile.type || 'text/plain'}
- Last Modified: ${new Date(selectedFile.lastModified).toLocaleString()}

Analysis Summary:
- Total Lines Processed: ${Math.floor(Math.random() * 10000) + 1000}
- Errors Found: ${Math.floor(Math.random() * 50)}
- Warnings Found: ${Math.floor(Math.random() * 100)}
- Info Messages: ${Math.floor(Math.random() * 500)}

Top Issues:
1. Connection timeout errors - 15 occurrences
2. Memory usage warnings - 8 occurrences
3. API rate limit warnings - 5 occurrences
4. Database query timeouts - 3 occurrences

Recommendations:
- Review connection pool settings
- Monitor memory allocation
- Implement rate limiting backoff
- Optimize database queries

Analysis completed at: ${new Date().toLocaleString()}
`;
      setResults(mockResults);
      setIsAnalyzing(false);
    }, 2000);
  };

  const handleClearResults = () => {
    setResults('');
  };

  const handleExit = () => {
    if (confirm('Are you sure you want to exit?')) {
      setSelectedFile(null);
      setFilePath('');
      setResults('');
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 to-slate-100 flex items-center justify-center p-8">
      <div className="w-full max-w-4xl bg-white rounded-lg shadow-xl border border-slate-200">
        {/* Header */}
        <div className="bg-gradient-to-r from-blue-600 to-blue-700 text-white px-6 py-4 rounded-t-lg">
          <div className="flex items-center gap-3">
            <FileText className="w-6 h-6" />
            <h1>DuCharme Triage Assistant</h1>
          </div>
        </div>

        {/* Main Content */}
        <div className="p-6 space-y-6">
          {/* File Selection Section */}
          <div className="space-y-3">
            <Label htmlFor="filePath" className="text-slate-700">
              Select Log File:
            </Label>
            <div className="flex gap-3">
              <Input
                id="filePath"
                type="text"
                value={filePath}
                placeholder="No file selected"
                readOnly
                className="flex-1 bg-slate-50"
              />
              <Button 
                onClick={handleBrowseClick}
                variant="outline"
                className="gap-2"
              >
                <Upload className="w-4 h-4" />
                Browse...
              </Button>
              <input
                id="fileInput"
                type="file"
                accept=".log,.txt,.json"
                onChange={handleFileSelect}
                className="hidden"
              />
            </div>
          </div>

          {/* Analyze Button */}
          <div>
            <Button 
              onClick={handleAnalyze}
              disabled={!selectedFile || isAnalyzing}
              className="w-full sm:w-auto bg-blue-600 hover:bg-blue-700"
            >
              {isAnalyzing ? 'Analyzing...' : 'Analyze'}
            </Button>
          </div>

          {/* Results Display Area */}
          <div className="space-y-2">
            <Label className="text-slate-700">Results:</Label>
            <ScrollArea className="h-80 w-full rounded-md border border-slate-200 bg-slate-50">
              <div className="p-4">
                <pre className="whitespace-pre-wrap text-slate-800">
                  {results || 'No results yet. Select a log file and click Analyze.'}
                </pre>
              </div>
            </ScrollArea>
          </div>

          {/* Action Buttons */}
          <div className="flex gap-3 pt-4 border-t border-slate-200">
            <Button
              onClick={handleClearResults}
              variant="outline"
              className="gap-2"
              disabled={!results}
            >
              <Trash2 className="w-4 h-4" />
              Clear Results
            </Button>
            <Button
              onClick={handleExit}
              variant="destructive"
              className="gap-2 ml-auto"
            >
              <X className="w-4 h-4" />
              Exit
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
