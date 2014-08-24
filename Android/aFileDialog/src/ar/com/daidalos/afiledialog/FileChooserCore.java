/*
 * «Copyright 2013 Jose F. Maldonado»
 *
 *  This file is part of aFileDialog.
 *
 *  aFileDialog is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published 
 *  by the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  aFileDialog is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with aFileDialog. If not, see <http://www.gnu.org/licenses/>.
 */

package ar.com.daidalos.afiledialog;

import java.io.*;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;

import android.content.Context;
import android.os.Environment;
import android.widget.LinearLayout;
import ar.com.daidalos.afiledialog.view.FileItem;

/**
 * This class implements the common features of a file chooser.
 */
class FileChooserCore
{
	/**
	 * This interface defines all the methods that a file chooser must
	 * implement, in order to being able to make use of the class
	 * FileChooserUtils.
	 */
	interface FileChooser
	{

		/**
		 * Gets the root of the layout 'file_chooser.xml'.
		 * 
		 * @return A linear layout.
		 */
		LinearLayout getRootLayout();

		/**
		 * Set the name of the current folder.
		 * 
		 * @param name
		 *            The current folder's name.
		 */
		void setCurrentFolderName(String name);

		/**
		 * Returns the current context of the file chooser.
		 * 
		 * @return The current context.
		 */
		Context getContext();
	}

	// ----- Attributes ----- //

	/**
	 * The file chooser in which all the operations are performed.
	 */
	private FileChooser chooser;

	/**
	 * The listeners for the event of select a file.
	 */
	private List<OnFileSelectedListener> listeners;

	/**
	 * A regular expression for filter the files.
	 */
	public String filter;

	/**
	 * A boolean indicating if only the files that can be selected (they pass
	 * the filter) must be show.
	 */
	public boolean showOnlySelectable;

	/**
	 * A boolean indicating if the chooser is going to be used to select
	 * folders.
	 */
	public boolean folderMode;

	/**
	 * A file that indicates the folder that is currently being displayed.
	 */
	File currentFolder;

	// ---- Static attributes ----- //

	/**
	 * Static attribute for save the folder displayed by default.
	 */
	private static File defaultFolder;

	/**
	 * Static constructor.
	 */
	static
	{
		defaultFolder = null;
	}

	// ----- Constructor ----- //

	/**
	 * Creates an instance of this class.
	 * 
	 * @param fileChooser
	 *            The graphical file chooser.
	 */
	public FileChooserCore(FileChooser fileChooser)
	{
		// Initialize attributes.
		this.chooser = fileChooser;
		this.listeners = new LinkedList<OnFileSelectedListener>();
		this.filter = null;
		this.showOnlySelectable = false;
		this.folderMode = false;
		this.currentFolder = null;
	}

	// ----- Events methods ----- //
	/**
	 * Implementation of the click listener for when a file item is clicked.
	 */
	private FileItem.OnFileClickListener fileItemClickListener = new FileItem.OnFileClickListener()
	{
		public void onClick(FileItem source)
		{
			// Verify if the item is a folder.
			File file = source.getFile();
			if (file.isDirectory())
			{
				// Open the folder.
				FileChooserCore.this.loadFolder(file);
			}
			else
			{
				// Notify the listeners.
				FileChooserCore.this.notifyListeners(file, null);
			}
		}
	};

	/**
	 * Add a listener for the event of a file selected.
	 * 
	 * @param listener
	 *            The listener to add.
	 */
	public void addListener(OnFileSelectedListener listener)
	{
		this.listeners.add(listener);
	}

	/**
	 * Removes a listener for the event of a file selected.
	 * 
	 * @param listener
	 *            The listener to remove.
	 */
	public void removeListener(OnFileSelectedListener listener)
	{
		this.listeners.remove(listener);
	}

	/**
	 * Removes all the listeners for the event of a file selected.
	 */
	public void removeAllListeners()
	{
		this.listeners.clear();
	}

	/**
	 * Interface definition for a callback to be invoked when a file is
	 * selected.
	 */
	public interface OnFileSelectedListener
	{
		/**
		 * Called when a file has been selected.
		 * 
		 * @param file
		 *            The file selected.
		 */
		void onFileSelected(File file);

		/**
		 * Called when an user wants to be create a file.
		 * 
		 * @param folder
		 *            The file's parent folder.
		 * @param name
		 *            The file's name.
		 */
		void onFileSelected(File folder, String name);
	}

	/**
	 * Notify to all listeners that a file has been selected or created.
	 * 
	 * @param file
	 *            The file or folder selected or the folder in which the file
	 *            must be created.
	 * @param name
	 *            The name of the file that must be created or 'null' if a file
	 *            was selected (instead of being created).
	 */
	void notifyListeners(final File file, final String name)
	{
		// Determine if a file has been selected or created.
		final boolean creation = name != null && name.length() > 0;

		// Notify to listeners.
		for (int i = 0; i < FileChooserCore.this.listeners.size(); i++)
		{
			if (creation)
			{
				FileChooserCore.this.listeners.get(i).onFileSelected(file, name);
			}
			else
			{
				FileChooserCore.this.listeners.get(i).onFileSelected(file);
			}
		}
	}

	// ----- Get and set methods ----- //

	/**
	 * Returns the current folder.
	 * 
	 * @return The current folder.
	 */
	public File getCurrentFolder()
	{
		return this.currentFolder;
	}

	// ----- Miscellaneous methods ----- //

	/**
	 * Loads all the files of the SD card root.
	 */
	public void loadFolder()
	{
		this.loadFolder(defaultFolder);
	}

	/**
	 * Loads all the files of a folder in the file chooser.
	 * 
	 * If no path is specified ('folderPath' is null) the root folder of the SD
	 * card is going to be used.
	 * 
	 * @param folderPath
	 *            The folder's path.
	 */
	public void loadFolder(String folderPath)
	{
		// Get the file path.
		File path = null;
		if (folderPath != null && folderPath.length() > 0)
			path = new File(folderPath);

		this.loadFolder(path);
	}

	/**
	 * Loads all the files of a folder in the file chooser.
	 * 
	 * If no path is specified ('folder' is null) the root folder of the SD card
	 * is going to be used.
	 * 
	 * @param folder
	 *            The folder.
	 */
	public void loadFolder(File folder)
	{
		// Remove previous files.
		LinearLayout root = this.chooser.getRootLayout();
		LinearLayout files_col0 = (LinearLayout) root.findViewById(R.id.files_col0);
		LinearLayout files_col1 = (LinearLayout) root.findViewById(R.id.files_col1);
		files_col0.removeAllViews();
		if(files_col1 != null)
			files_col1.removeAllViews();

		// Get the file path.
		if (folder == null || !folder.exists())
		{
			if (defaultFolder != null)
			{
				this.currentFolder = defaultFolder;
			}
			else
			{
				this.currentFolder = Environment.getExternalStorageDirectory();
			}
		}
		else
		{
			this.currentFolder = folder;
		}

		// Verify if the path exists.
		if (this.currentFolder.exists() && files_col0 != null)
		{
			List<FileItem> fileItems = new LinkedList<FileItem>();

			// Add the parent folder.
			if (this.currentFolder.getParent() != null)
			{
				File parent = new File(this.currentFolder.getParent());
				if (parent.exists())
				{
					fileItems.add(new FileItem(this.chooser.getContext(), parent, ".."));
				}
			}

			// Verify if the file is a directory.
			if (this.currentFolder.isDirectory())
			{
				// Get the folder's files.
				File[] fileList = this.currentFolder.listFiles();
				if (fileList != null)
				{
					// Order the files alphabetically and separating folders
					// from files.
					Arrays.sort(fileList, new Comparator<File>()
					{
						public int compare(File file1, File file2)
						{
							if (file1 != null && file2 != null)
							{
								if (file1.isDirectory() && (!file2.isDirectory()))
									return -1;
								if (file2.isDirectory() && (!file1.isDirectory()))
									return 1;
								return file1.getName().compareTo(file2.getName());
							}
							return 0;
						}
					});

					// Iterate all the files in the folder.
					for (int i = 0; i < fileList.length; i++)
					{
						// Verify if file can be selected (is a directory or
						// folder mode is not activated and the file pass the
						// filter, if defined).
						boolean selectable = true;
						if (!fileList[i].isDirectory())
							selectable = !this.folderMode && (this.filter == null || fileList[i].getName().matches(this.filter));		

						// Verify if the file must be show.
						if (!fileList[i].isHidden() && (selectable || !this.showOnlySelectable))
						{
							// Create the file item and add it to the list.
							FileItem fileItem = new FileItem(this.chooser.getContext(), fileList[i]);
							fileItem.setSelectable(selectable);
							fileItems.add(fileItem);
						}
					}
				}

				// Set the name of the current folder.
				String currentFolderName = this.currentFolder.getPath();
				this.chooser.setCurrentFolderName(currentFolderName);
			}
			else
			{
				// The file is not a folder, add only this file.
				fileItems.add(new FileItem(this.chooser.getContext(), this.currentFolder));
			}

			// Add click listener and add the FileItem objects to the layout.
			for (int i = 0; i < fileItems.size(); i++)
			{
				fileItems.get(i).addListener(this.fileItemClickListener);
				if(files_col1 != null && i%2 == 1)
					files_col1.addView(fileItems.get(i));
				else
					files_col0.addView(fileItems.get(i));
			}

			// Refresh default folder.
			defaultFolder = this.currentFolder;
		}
	}
}
