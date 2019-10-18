/*
 * Copyright 2013 Jose F. Maldonado
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

import java.io.File;
import java.util.LinkedList;
import java.util.List;

import ar.com.daidalos.afiledialog.R;

import android.app.AlertDialog;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.view.LayoutInflater;
import android.view.View;
import android.view.WindowManager;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * A file chooser implemented in a Dialog.
 */
public class FileChooserDialog implements FileChooserCore.FileChooser
{
	private Context context;
	private Dialog dialog;
	private String title = null;
	LayoutInflater inflater;
	// ----- Attributes ----- //

	/**
	 * The core of this file chooser.
	 */
	private FileChooserCore core;

	/**
	 * The listeners for the event of select a file.
	 */
	private List<OnFileSelectedListener> listeners;
	TextView dir_path;

	// ----- Constructors ----- //

	/**
	 * Creates a file chooser dialog which, by default, lists all the files in
	 * the SD card.
	 * 
	 * @param context
	 *            The current context.
	 */
	public FileChooserDialog(Context context, String title, LayoutInflater inflater)
	{
		this.context = context;
		this.title = title;
		this.inflater = inflater;
		this.core = new FileChooserCore(this);
		this.listeners = new LinkedList<OnFileSelectedListener>();
	}
	public void show()
	{
		// Create the dialog
		AlertDialog.Builder builder = new AlertDialog.Builder(context);
	    builder.setTitle(title).setView(inflater.inflate(R.layout.daidalos_file_chooser, null));
		
	    // Add OK button if selecting folders
		if(this.core.folderMode)
		{
			builder.setPositiveButton("OK", new DialogInterface.OnClickListener()
			{
				public void onClick(DialogInterface dialog, int id)
				{
					core.notifyListeners(core.currentFolder, null);
				}
			});
		}
	    
	    dialog = builder.create();
	    dialog.show();
	    
	    dir_path = (TextView) dialog.findViewById(R.id.dir_path);
		// Maximize the dialog.
		WindowManager.LayoutParams lp = new WindowManager.LayoutParams();
		lp.copyFrom(dialog.getWindow().getAttributes());
		lp.width = WindowManager.LayoutParams.MATCH_PARENT;
		lp.height = WindowManager.LayoutParams.MATCH_PARENT;
		dialog.getWindow().setAttributes(lp);

		// By default, load the SD card files.
		this.core.loadFolder("");

		// Add a listener for when a file is selected.
		core.addListener(new FileChooserCore.OnFileSelectedListener()
		{
			public void onFileSelected(File folder, String name)
			{
				// Call to the listeners.
				for (int i = 0; i < FileChooserDialog.this.listeners.size(); i++)
					FileChooserDialog.this.listeners.get(i).onFileSelected(dialog, folder, name);
			}

			public void onFileSelected(File file)
			{
				// Call to the listeners.
				for (int i = 0; i < FileChooserDialog.this.listeners.size(); i++)
					FileChooserDialog.this.listeners.get(i).onFileSelected(dialog, file);
			}
		});
	}

	// ----- Events methods ----- //

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
		void onFileSelected(Dialog source, File file);

		/**
		 * Called when an user wants to be create a file.
		 * 
		 * @param folder
		 *            The file's parent folder.
		 * @param name
		 *            The file's name.
		 */
		void onFileSelected(Dialog source, File folder, String name);
	}

	// ----- Miscellaneous methods ----- //

	/**
	 * Set a regular expression to filter the files that can be selected.
	 * 
	 * @param filter
	 *            A regular expression.
	 */
	public void setFilter(String filter)
	{
		this.core.filter = filter;
	}

	/**
	 * Defines if only the files that can be selected (they pass the filter)
	 * must be show.
	 * 
	 * @param show
	 *            'true' if only the files that can be selected must be show or
	 *            'false' if all the files must be show.
	 */
	public void setShowOnlySelectable(boolean show)
	{
		this.core.showOnlySelectable = show;
	}

	/**
	 * Loads all the files of the SD card root.
	 */
	public void loadFolder()
	{
		this.core.loadFolder();
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
		this.core.loadFolder(folderPath);
	}

	/**
	 * Defines if the chooser is going to be used to select folders, instead of
	 * files.
	 * 
	 * @param folderMode
	 *            'true' for select folders or 'false' for select files.
	 */
	public void setFolderMode(boolean folderMode)
	{
		this.core.folderMode = folderMode;
	}


	// ----- FileChooser methods ----- //
	public LinearLayout getRootLayout()
	{
		View root = dialog.findViewById(R.id.rootLayout);
		return (root instanceof LinearLayout) ? (LinearLayout) root : null;
	}

	public void setCurrentFolderName(String name)
	{
		dir_path.setText(name);
	}

	@Override
	public Context getContext()
	{
		return context;
	}
}
